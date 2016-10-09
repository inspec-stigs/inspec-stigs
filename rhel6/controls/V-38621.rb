# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38621 - The system clock must be synchronized to an authoritative DoD time source.'

control 'V-38621' do
  impact 0.5
  title 'The system clock must be synchronized to an authoritative DoD time source.'
  desc '
Synchronizing with an NTP server makes it possible to collate system logs from multiple sources or correlate computer events with real time events. Using a trusted NTP server provided by your organization is recommended.
'
  tag 'stig','V-38621'
  tag severity: 'medium'
  tag checkid: 'C-46180r1_chk'
  tag fixid: 'F-43570r1_fix'
  tag version: 'RHEL-06-000248'
  tag ruleid: 'SV-50422r1_rule'
  tag fixtext: '
To specify a remote NTP server for time synchronization, edit the file "/etc/ntp.conf". Add or correct the following lines, substituting the IP or hostname of a remote NTP server for ntpserver.

server [ntpserver]

This instructs the NTP software to contact that remote server to obtain time data.
'
  tag checktext: '
A remote NTP server should be configured for time synchronization. To verify one is configured, open the following file.

/etc/ntp.conf

In the file, there should be a section similar to the following:

# --- OUR TIMESERVERS -----
server [ntpserver]


If this is not the case, this is a finding.
'

# START_DESCRIBE V-38621
  tag 'ntp','ntp.conf'
  options = {
    assignment_re: /^(.*?)\s+(.*)$/
  }
  describe parse_config_file('/etc/ntp.conf',options) do
    its('server') { should match /.*/ }
  end
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE V-38621

end
