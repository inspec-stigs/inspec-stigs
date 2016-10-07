# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38492 - The system must prevent the root account from logging in from virtual consoles.'

control 'V-38492' do
  impact 0.5
  title 'The system must prevent the root account from logging in from virtual consoles.'
  desc '
Preventing direct root login to virtual console devices helps ensure accountability for actions taken on the system using the root account. 
'
  tag 'stig','V-38492'
  tag severity: 'medium'
  tag checkid: 'C-46049r1_chk'
  tag fixid: 'F-43439r2_fix'
  tag version: 'RHEL-06-000027'
  tag ruleid: 'SV-50293r1_rule'
  tag fixtext: '
To restrict root logins through the (deprecated) virtual console devices, ensure lines of this form do not appear in "/etc/securetty": 

vc/1
vc/2
vc/3
vc/4

Note:  Virtual console entries are not limited to those listed above.  Any lines starting with "vc/" followed by numerals should be removed.
'
  tag checktext: '
To check for virtual console entries which permit root login, run the following command: 

# grep \'^vc/[0-9]\' /etc/securetty

If any output is returned, then root logins over virtual console devices is permitted. 
If root login over virtual console devices is permitted, this is a finding.
'

# START_CHECKS
  # describe file('/etc') do
  #  it { should be_directory }
  #end
# END_CHECKS
end
