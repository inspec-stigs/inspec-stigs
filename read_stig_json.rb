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

puts $input
puts $dest


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

#  describe service('autofs') do
#    it { should_not be_enabled }
#    it { should_not be_running }
#  end

controls = stig['findings'].keys
#findings = stig['findings']

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

    # START_CHECKS
      # describe file('/etc') do
      #  it { should be_directory }
      #end
    # END_CHECKS
    end
  HEREDOC

  File.write("#{$dest}/#{control}.rb", output)

end

