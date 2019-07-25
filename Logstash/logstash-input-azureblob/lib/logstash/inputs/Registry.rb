require 'json'
require 'forwardable'

require "#{__dir__}/RegistryItem.rb"

class Registry
	def initialize(opts={})
		@itemClass = opts[:itemClass] || RegistryItem
		@content = opts[:content] || {}
	end
	attr_reader :itemClass, :content
	extend Forwardable
	def_delegators :content, :[], :each, :to_json
	def names
		content.keys
	end
	def items
		content.values
	end

	def contentFromJson(json)
		@content = {}
		JSON.parse(json).each {|key, value|
			add(itemClass.fromHash(value))
		}
		self
	end

	def add(item)
		content[item.file_path] = item
	end
	def addByData(*args)
		add(itemClass.new(*args))
	end

	def remove(filePath)
		content.delete(filePath)
	end
	def removeMany(filePaths)
		filePaths.each {|filePath|
			remove(filePath)
		}
	end

	def unregisterReader(reader)
		each {|key, item|
			item.reader = nil if item.reader == reader
		}
		self
	end
end
