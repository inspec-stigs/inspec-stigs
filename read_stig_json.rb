#!/usr/bin/ruby

# this is a really dirty script to parse a STIG from JSON format and
# create inspec controls for them

# created the rhel6 stig with the following:
# $ mkdir json
# $ wget -O json/rhel6.json https://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2015-05-26/MAC-3_Sensitive/json
# $ inspec init profile rhel6
# $ ./read_stig_json.rb -i json/rhel6.json -d rhel6/controls

require 'json'
require 'optparse'

OptionParser.new do |o|
  o.on('-i FILENAME') { |i| $input = i }
  o.on('-d FILENAME') { |d| $dest = d }
  o.on('-h') { puts o; exit }
  o.parse!
end

input = File.read($input)

parsed = JSON.parse(input)

stig = parsed['stig']

#puts JSON.pretty_generate(stig)

def safe(input)
  input.gsub("'", "\\\\'")
end

def impact(input)
  if input == "low"
    output = 0.1
  elsif input == "medium"
    output = 0.5
  else
    output = 1.0
  end
  output
end

def make_inspec_rule(control)
  inspec_file = "src/inspec/#{control}.rb"
  if ! File.file?(inspec_file)
    inspec = <<~HEREDOC
      # START_DESCRIBE #{control}
        # describe file('/etc') do
        #   it { should be_directory }
        # end
      # END_DESCRIBE #{control}
    HEREDOC
    puts "writing #{inspec_file}"
    File.write(inspec_file, inspec)
  else
    puts "reading #{inspec_file}"
    inspec = File.read(inspec_file)
  end
  inspec
end

#  describe service('autofs') do
#    it { should_not be_enabled }
#    it { should_not be_running }
#  end

controls = stig['findings'].keys

controls.each do |control|
  finding = stig['findings'][control]

  output = <<~HEREDOC
    # encoding: utf-8
    # copyright: 2016, you
    # license: All rights reserved
    # date: #{stig["date"]}
    # description: #{stig["description"]}
    # impacts

    title '#{control} - #{finding['title']}'

    control '#{control}' do
      impact #{impact(finding['severity'])}
      title '#{finding['title']}'
      desc '\n#{safe(finding['description'])}\n'
      tag 'stig','#{control}'
      tag severity: '#{finding['severity']}'
      tag checkid: '#{finding['checkid']}'
      tag fixid: '#{finding['fixid']}'
      tag version: '#{finding['version']}'
      tag ruleid: '#{finding['ruleID']}'
      tag fixtext: '\n#{safe(finding['fixtext'])}\n'
      tag checktext: '\n#{safe(finding['checktext'])}\n'

    #{make_inspec_rule(control)}
    end
  HEREDOC

  #File.write("#{$dest}/#{control}.rb", output)

end

