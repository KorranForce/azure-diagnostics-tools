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
	def_delegators :content, :[], :each, :values, :to_json

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
	def unregisterReader(reader)
		each {|key, item|
			item.reader = nil if item.reader == reader
		}
		self
	end
end
