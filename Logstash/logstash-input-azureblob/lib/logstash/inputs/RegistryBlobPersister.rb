require "#{__dir__}/Registry.rb"

class RegistryBlobPersister
	def initialize(opts={})
		@registryClass = opts[:registryClass] || Registry
		@azureBlob = opts[:azureBlob] || raise("azureBlob must be specified")
		@container = opts[:container] || raise("container must be specified")
		@leaseDuration = opts[:leaseDuration] || raise("leaseDuration must be specified")
		@registryPath = opts[:registryPath] || raise("registryPath must be specified")
	end
	attr_reader :registryClass, :azureBlob, :container, :registryPath, :leaseDuration

	def load
		_blob, blobBody = azureBlob.get_blob(container, registryPath)
		registryClass.new.contentFromJson(blobBody)
	end
	def save(registry, leaseId=nil)
		azureBlob.create_block_blob(container, registryPath, registry.to_json, lease_id: leaseId)
	end
	def create
		registry = registryClass.new
		save(registry)
		registry
	end

	def update(registryItem)
		leaseId = nil
		begin
			leaseId = acquireLease
			registry = load
			registry.add(registryItem)
			save(registry, leaseId)
		ensure
			releaseLease(leaseId) if leaseId
		end
	end
	def unregisterReader(reader)
		leaseId = nil
		begin
			leaseId = acquireLease
			registry = load
			registry.unregisterReader(reader)
			save(registry, leaseId)
		ensure
			releaseLease(leaseId) if leaseId
		end
	end

	def acquireLease(retryTimes:60, intervalSec:1)
		leaseId = nil;
		retried = 0;
		while leaseId.nil?
			begin
				leaseId = azureBlob.acquire_blob_lease(container, registryPath, {timeout: 60, duration: leaseDuration})
			rescue StandardError=> exc
				if exc.class.name.include?('LeaseAlreadyPresent')
					if retried > retryTimes
						raise
					end
					retried += 1
					sleep intervalSec
				else
					# Anything else happend other than 'LeaseAlreadyPresent', break the lease. This is a work-around for the behavior that when
					# timeout exception is hit, somehow, a infinite lease will be put on the lock file.
					azureBlob.break_blob_lease(container, registryPath, {break_period: 30})
				end
			end
		end
		return leaseId
	end
	def releaseLease(leaseId)
		azureBlob.release_blob_lease(container, registryPath, leaseId)
	end
end