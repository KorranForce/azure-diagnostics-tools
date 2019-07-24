# Registry item to coordinate between mulitple clients
class LogStash::Inputs::RegistryItem
	def self.fromHash(hash)
		new(hash['file_path'], hash['etag'], hash['reader'], hash['offset'], hash['gen'])
	end
	def initialize(file_path, etag, reader, offset = 0, gen = 0)
		@file_path = file_path
		@etag = etag
		@reader = reader
		@offset = offset
		@gen = gen
	end
	attr_accessor :file_path, :etag, :offset, :reader, :gen

	def as_json(options={})
		{
			file_path: @file_path,
			etag: @etag,
			reader: @reader,
			offset: @offset,
			gen: @gen
		}
	end
	def to_json(*options)
		as_json(*options).to_json(*options)
	end
end
