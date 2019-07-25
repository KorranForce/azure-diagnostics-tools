require 'json'
require 'forwardable'

require "#{__dir__}/RegistryItem.rb"

class LogStash::Inputs::Registry
	def initialize(opts={})
		@itemClass = opts[:itemClass] || LogStash::Inputs::RegistryItem
		@content = opts[:content] || {}
	end
	attr_reader :itemClass, :content
	extend Forwardable
	def_delegators :content, :[], :each, :values, :to_json

	def contentFromJson(json)
		@content = {}
		JSON.parse(json).each {|key, value|
			@content[key] = itemClass.fromHash(value)
		}
		self
	end
	def add(item)
		content[item.file_path] = item
	end
end
