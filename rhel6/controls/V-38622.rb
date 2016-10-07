# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38622 - Mail relaying must be restricted.'

control 'V-38622' do
  impact 0.5
  title 'Mail relaying must be restricted.'
  desc '
This ensures "postfix" accepts mail messages (such as cron job reports) from the local system only, and not from the network, which protects it from network attack.
'
  tag 'stig','V-38622'
  tag severity: 'medium'
  tag checkid: 'C-46182r2_chk'
  tag fixid: 'F-43572r1_fix'
  tag version: 'RHEL-06-000249'
  tag ruleid: 'SV-50423r2_rule'
  tag fixtext: '
Edit the file "/etc/postfix/main.cf" to ensure that only the following "inet_interfaces" line appears: 

inet_interfaces = localhost
'
  tag checktext: '
If the system is an authorized mail relay host, this is not applicable. 

Run the following command to ensure postfix accepts mail messages from only the local system: 

$ grep inet_interfaces /etc/postfix/main.cf

If properly configured, the output should show only "localhost". 
If it does not, this is a finding.
'

# START_CHECKS
  # describe file('/etc') do
  #  it { should be_directory }
  #end
# END_CHECKS
end
