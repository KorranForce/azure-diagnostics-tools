class BlobReader < LinearReader
	def initialize(logger, azure_blob, container, blob_name, chunk_size, blob_start_index, blob_end_index)
		@logger = logger
		@azure_blob = azure_blob
		@container = container
		@blob_name = blob_name
		@blob_start_index = blob_start_index
		@blob_end_index = blob_end_index
		@chunk_size = chunk_size
	end

	def read
		return nil, false if @blob_end_index < @blob_start_index

		end_index = @blob_end_index
		are_more_bytes_available = false
		if @blob_end_index >= @blob_start_index + @chunk_size
			end_index = @blob_start_index + @chunk_size - 1
			are_more_bytes_available = true
		end

		content = read_from_blob(@blob_start_index, end_index)
		@blob_start_index = end_index + 1

		return content, are_more_bytes_available
	end

	private

	def read_from_blob(start_index, end_index)
		_blob, content = @azure_blob.get_blob(@container, @blob_name, {start_range: start_index, end_range: end_index})
		return content
	end
end
