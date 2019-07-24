# encoding: utf-8
require "logstash/inputs/base"
require "logstash/namespace"

require "azure/storage/blob"

require 'json' # for registry content
require "securerandom" # for generating uuid.

require "com/microsoft/json-parser"

#require Dir[ File.dirname(__FILE__) + "/../../*_jars.rb" ].first
require "#{__dir__}/BlobReader.rb"
require "#{__dir__}/RegistryItem.rb"
require "#{__dir__}/Registry.rb"

# Logstash input plugin for Azure Blobs
#
# This logstash plugin gathers data from Microsoft Azure Blobs
class LogStash::Inputs::LogstashInputAzureblob < LogStash::Inputs::Base
	config_name 'azureblob'

	# If undefined, Logstash will complain, even if codec is unused.
	default :codec, 'json_lines'

	# Set the account name for the azure storage account.
	config :storage_account_name, validate: :string

	# Set the key to access the storage account.
	config :storage_access_key, validate: :string

	# Set the container of the blobs.
	config :container, validate: :string
	
	# The path(s) to the file(s) to use as an input. By default it will
	# watch every files in the storage container.
	# You can use filename patterns here, such as `logs/*.log`.
	# If you use a pattern like `logs/**/*.log`, a recursive search
	# of `logs` will be done for all `*.log` files.
	# Do not include a leading `/`, as Azure path look like this:
	# `path/to/blob/file.txt`
	#
	# You may also configure multiple paths. See an example
	# on the <<array,Logstash configuration page>>.
	config :path_filters, validate: :array, default: [], required: false

	# Set the endpoint for the blobs.
	#
	# The default, `core.windows.net` targets the public azure.
	config :endpoint, validate: :string, default: 'core.windows.net'

	# Set the value of using backup mode.
	config :backupmode, validate: :boolean, default: false, deprecated: true, obsolete: 'This option is obsoleted and the settings will be ignored.'

	# Set the value for the registry file.
	#
	# The default, `data/registry`, is used to coordinate readings for various instances of the clients.
	config :registry_path, validate: :string, default: 'data/registry'

	# Sets the value for registry file lock duration in seconds. It must be set to -1, or between 15 to 60 inclusively.
	#
	# The default, `15` means the registry file will be locked for at most 15 seconds. This should usually be sufficient to 
	# read the content of registry. Having this configuration here to allow lease expired in case the client crashed that 
	# never got a chance to release the lease for the registry.
	config :registry_lease_duration, validate: :number, default: 15

	# Set how many seconds to keep idle before checking for new logs.
	#
	# The default, `30`, means trigger a reading for the log every 30 seconds after entering idle.
	config :interval, validate: :number, default: 30

	# Set the registry create mode
	#
	# The default, `resume`, means when the registry is initially created, it assumes all logs has been handled.
	# When set to `start_over`, it will read all log files from begining.
	config :registry_create_policy, validate: :string, default: 'resume'

	# Sets the header of the file that does not repeat over records. Usually, these are json opening tags.
	config :file_head_bytes, validate: :number, default: 0

	# Sets the tail of the file that does not repeat over records. Usually, these are json closing tags.
	config :file_tail_bytes, validate: :number, default: 0

	# Sets how to break json
	#
	# Only works when the codec is set to `json`. Sets the policy to break the json object in the array into small events.
	# Break json into small sections will not be as efficient as keep it as a whole, but will reduce the usage of 
	# the memory. 
	# Possible options: `do_not_break`, `with_head_tail`, `without_head_tail`
	config :break_json_down_policy, validate: :string, default: 'do_not_break', obsolete: 'This option is obsoleted and the settings will be ignored.'

	# Sets when break json happens, how many json object will be put in 1 batch
	config :break_json_batch_count, validate: :number, default: 10, obsolete: 'This option is obsoleted and the settings will be ignored.'

	# Sets the page-size for returned blob items. Too big number will hit heap overflow; Too small number will leads to too many requests.
	#
	# The default, `100` is good for default heap size of 1G.
	config :blob_list_page_size, validate: :number, default: 100

	# The default is 4 MB
	config :file_chunk_size_bytes, validate: :number, default: 4 * 1024 * 1024

	config :azure_blob_file_path_field, validate: :boolean, default: false

	config :azure_blob_file_path_field_name, validate: :string, default: "azureblobfilepath"

	# Constant of max integer
	MAX = 2**([42].pack('i').size * 16 - 2) - 1

	# Update the registry offset each time after this number of entries have been processed
	UPDATE_REGISTRY_COUNT = 100

	public
	def register
		user_agent = "logstash-input-azureblob/#{Gem.latest_spec_for('logstash-input-azureblob').version}"

		@path_filters << registry_path unless path_filters.include?(registry_path)

		# this is the reader # for this specific instance.
		@reader = SecureRandom.uuid

		@azure_blob = Azure::Storage::Blob::BlobService.create(
			storage_dns_suffix: endpoint,
			storage_account_name: storage_account_name,
			storage_access_key: storage_access_key,
			user_agent_prefix: user_agent)
		# Add retry filter to the service object
		@azure_blob.with_filter(Azure::Storage::Common::Core::Filter::ExponentialRetryPolicyFilter.new)
	end

	def run(queue)
		# we can abort the loop if stop? becomes true
		while !stop?
			process(queue)
			@logger.debug("Hitting interval of #{interval}s . . .")
			Stud.stoppable_sleep(interval) {stop?}
		end
	end

	def stop
		cleanup_registry
	end

	# Start processing the next item.
	def process(queue)
		begin
			@processed_entries = 0
			blob, start_index, gen = register_for_read

			if blob
				begin
					blob_name = blob.name
					@logger.debug("Processing blob #{blob_name}")
					blob_size = blob.properties[:content_length]
					# Work-around: After returned by get_blob, the etag will contain quotes.
					new_etag = blob.properties[:etag]
					# ~ Work-around
					blob, header = @azure_blob.get_blob(container, blob_name, {end_range: file_head_bytes - 1}) if file_head_bytes && file_head_bytes > 0
					blob, tail = @azure_blob.get_blob(container, blob_name, {start_range: blob_size - file_tail_bytes}) if file_tail_bytes && file_tail_bytes > 0
					blob = nil #gc

					# Skip the header since it is already read.
					start_index = file_head_bytes if start_index == 0

					@logger.debug("start index: #{start_index} blob size: #{blob_size}")

					content_length = 0
					blob_reader = BlobReader.new(@logger, @azure_blob, container, blob_name, file_chunk_size_bytes, start_index, blob_size - 1 - file_tail_bytes)

					is_json_codec = (defined?(LogStash::Codecs::JSON) == 'constant') && (@codec.is_a? LogStash::Codecs::JSON)
					if is_json_codec
						parser = JsonParser.new(@logger, blob_reader)

						parser.parse(
							->(json_content) {
								content_length += json_content.length

								enqueue_content(queue, json_content, header, tail, blob_name)

								on_entry_processed(start_index, content_length, blob_name, new_etag, gen)
							},
							->(malformed_json) {
								@logger.debug("Skipping #{malformed_json.length} malformed bytes")
								content_length = content_length + malformed_json.length

								on_entry_processed(start_index, content_length, blob_name, new_etag, gen)
							})
					else
						begin
							content, are_more_bytes_available = blob_reader.read

							content_length += content.length
							enqueue_content(queue, content, header, tail, blob_name)

							on_entry_processed(start_index, content_length, blob_name, new_etag, gen)
						end while are_more_bytes_available && content
					end
				ensure
					# Making sure the reader is removed from the registry even when there's exception.
					request_registry_update(start_index, content_length, blob_name, new_etag, gen)
				end
			end
		rescue => exc
			log_error(exc)
		end
	end

	def enqueue_content(queue, content, header, tail, blob_name)
		if (header.nil? || header.length == 0) && (tail.nil? || tail.length == 0)
			#skip some unnecessary copying
			full_content = content
		else
			full_content = ''
			full_content << header unless header.nil? || header.length == 0
			full_content << content
			full_content << tail unless tail.nil? || tail.length == 0
		end

		codec.decode(full_content) {|event|
			if @azure_blob_file_path_field
				event.set(@azure_blob_file_path_field_name, blob_name)
			end
			decorate(event)
			queue << event
		}
	end

	def on_entry_processed(start_index, content_length, blob_name, new_etag, gen)
		@processed_entries += 1
		request_registry_update(start_index, content_length, blob_name, new_etag, gen) if @processed_entries % UPDATE_REGISTRY_COUNT == 0
	end

	# List all the blobs in the given container.
	def list_all_blobs
		blobs = Set.new
		@blob_list_page_size = 100 if blob_list_page_size <= 0

		if path_filters.any?
			merger = ->(blobs, entries){
				entries.each {|entry|
					# FNM_PATHNAME is required so that "**/test" can match "test" at the root folder
					# FNM_EXTGLOB allows you to use "test{a,b,c}" to match either "testa", "testb" or "testc" (closer to shell behavior)
					blobs << entry if path_filters.any? {|path| File.fnmatch?(path, entry.name, File::FNM_PATHNAME | File::FNM_EXTGLOB)}
				}
			}
		else
			merger = ->(blobs, entries){blobs.merge(entries)}
		end

		continuation_token = nil
		begin
			# Need to limit the returned number of the returned entries to avoid out of memory exception.
			entries = @azure_blob.list_blobs(container, {timeout: 60, marker: continuation_token, max_results: blob_list_page_size})
			continuation_token = entries.continuation_token
			merger.call(blobs, entries)
		end until continuation_token.empty?

		return blobs
	end

	# Acquire a lease on a blob item with retries.
	#
	# By default, it will retry 60 times with 1 second interval.
	def acquire_lease(blob_name, retry_times = 60, interval_sec = 1)
		lease = nil;
		retried = 0;
		while lease.nil?
			begin
				lease = @azure_blob.acquire_blob_lease(container, blob_name, {timeout: 60, duration: registry_lease_duration})
			rescue StandardError=> exc
				if exc.class.name.include?('LeaseAlreadyPresent')
					if retried > retry_times
						raise
					end
					retried += 1
					sleep interval_sec
				else
					# Anything else happend other than 'LeaseAlreadyPresent', break the lease. This is a work-around for the behavior that when
					# timeout exception is hit, somehow, a infinite lease will be put on the lock file.
					@azure_blob.break_blob_lease(container, blob_name, {break_period: 30})
				end
			end
		end
		return lease
	end

	def request_registry_update(start_index, content_length, blob_name, new_etag, gen)
		new_offset = start_index
		new_offset += content_length unless content_length.nil?
		@logger.debug("New registry offset: #{new_offset}")
		new_registry_item = LogStash::Inputs::RegistryItem.new(blob_name, new_etag, nil, new_offset, gen)
		update_registry(new_registry_item)
	end

	# Return the next blob for reading as well as the start index.
	def register_for_read
		begin
			all_blobs = list_all_blobs
			registryBlob = all_blobs.find {|item| item.name.downcase == registry_path}
			
			candidate_blobs = all_blobs.select {|item| item.name.downcase != registry_path}
			all_blobs = nil #gc

			if registryBlob
				registry = load_registry
				lease = acquire_lease(registry_path)
			else
				registry = create_registry(candidate_blobs)
				lease = acquire_lease(registry_path)
			end

			picked_blobs = Set.new
			# Pick up the next candidate
			picked_blob = nil
			candidate_blobs.each {|candidate_blob|
				@logger.debug("candidate_blob: #{candidate_blob.name} content length: #{candidate_blob.properties[:content_length]}")
				registry_item = registry[candidate_blob.name]

				# Appending items that doesn't exist in the hash table
				if registry_item.nil?
					registry_item = LogStash::Inputs::RegistryItem.new(candidate_blob.name, candidate_blob.properties[:etag], nil, 0, 0)
					registry[candidate_blob.name] = registry_item
				end
				@logger.debug("registry_item offset: #{registry_item.offset}")
				if ((registry_item.offset < candidate_blob.properties[:content_length]) && (registry_item.reader.nil? || registry_item.reader == @reader))
					@logger.debug("candidate_blob picked: #{candidate_blob.name} content length: #{candidate_blob.properties[:content_length]}")
					picked_blobs << candidate_blob
				end
			}
			candidate_blobs = nil #gc

			picked_blob = picked_blobs.min_by {|b| registry[b.name].gen}
			picked_blobs = nil #gc

			start_index = 0
			gen = 0
			if picked_blob
				registry_item = registry[picked_blob.name]
				registry_item.reader = @reader
				start_index = registry_item.offset
				raise_gen(registry, picked_blob.name)
				gen = registry_item.gen
			end

			# Save the change for the registry
			save_registry(registry, lease)

			@azure_blob.release_blob_lease(container, registry_path, lease)
			lease = nil

			return picked_blob, start_index, gen
		rescue StandardError=> exc
			log_error(exc)
			return nil, nil, nil
		ensure
			@azure_blob.release_blob_lease(container, registry_path, lease) if lease
		end
	end

	# Raise generation for blob in registry
	def raise_gen(registry, file_path)
		begin
			target_item = registry[file_path]
			begin
				target_item.gen += 1
				# Protect gen from overflow.
				target_item.gen = target_item.gen / 2 if target_item.gen == MAX
			rescue StandardError=> exc
				@logger.error("Fail to get the next generation for target item #{target_item}.", exception: exc)
				target_item.gen = 0
			end

			min_gen_item = registry.values.min_by {|x| x.gen}
			while min_gen_item.gen > 0
				registry.values.each {|value| 
					value.gen -= 1
				}
				min_gen_item = registry.values.min_by {|x| x.gen}
			end
		end
	end

	def update_registry(registry_item)
		begin
			lease = nil
			lease = acquire_lease(registry_path)
			registry = load_registry
			registry[registry_item.file_path] = registry_item
			save_registry(registry, lease)
			@azure_blob.release_blob_lease(container, registry_path, lease)
			lease = nil
		rescue StandardError=> exc
			log_error(exc)
		ensure
			@azure_blob.release_blob_lease(container, registry_path, lease) if lease
		end
	end

	def cleanup_registry
		begin
			@logger.debug("azureblob : start cleanup_registry")
			lease = nil
			lease = acquire_lease(registry_path)
			registry = load_registry
			registry.each {|key, item|
				item.reader = nil if item.reader == @reader
			}
			save_registry(registry, lease)
			@azure_blob.release_blob_lease(container, registry_path, lease)
			lease = nil
		rescue StandardError=> exc
			log_error(exc)
		ensure
			@azure_blob.release_blob_lease(container, registry_path, lease) if lease
		end
		@logger.debug("azureblob : End of cleanup_registry")
	end

	# Create a registry file to coordinate between multiple azure blob inputs.
	def create_registry(blob_items)
		@azure_blob.create_block_blob(container, registry_path, '')
		lease = acquire_lease(registry_path)
		registry = LogStash::Inputs::Registry.new
		if registry_create_policy == 'resume'
			initialOffsetGetter = ->(blob){blob.properties[:content_length]}
		else
			initialOffsetGetter = ->(blob){0}
		end
		blob_items.each {|blob_item|
			registry[blob_item.name] = LogStash::Inputs::RegistryItem.new(blob_item.name, blob_item.properties[:etag], nil, initialOffsetGetter.call(blob_item), 0)
		}
		save_registry(registry, lease)
		@azure_blob.release_blob_lease(container, registry_path, lease)
		registry
	end

	# Load the content of the registry into the registry hash and return it.
	def load_registry
		# Get content
		_registry_blob, registry_blob_body = @azure_blob.get_blob(container, registry_path)
		LogStash::Inputs::Registry.new.contentFromJson(registry_blob_body)
	end

	# Serialize the registry hash and save it.
	def save_registry(registry, lease_id)
		registry_json = registry.to_json

		@azure_blob.create_block_blob(container, registry_path, registry_json, lease_id: lease_id)
	end

	def log_error(exc)
		@logger.error("Oh My, An error occurred. #{exc}:\n#{exc.backtrace}", exception: exc)
	end
end
