# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38477 - Users must not be able to change passwords more than once every 24 hours.'

control 'V-38477' do
  impact 0.5
  title 'Users must not be able to change passwords more than once every 24 hours.'
  desc '
Setting the minimum password age protects against users cycling back to a favorite password after satisfying the password reuse requirement.
'
  tag 'stig','V-38477'
  tag severity: 'medium'
  tag checkid: 'C-46032r1_chk'
  tag fixid: 'F-43422r1_fix'
  tag version: 'RHEL-06-000051'
  tag ruleid: 'SV-50277r1_rule'
  tag fixtext: '
To specify password minimum age for new accounts, edit the file "/etc/login.defs" and add or correct the following line, replacing [DAYS] appropriately: 

PASS_MIN_DAYS [DAYS]

A value of 1 day is considered sufficient for many environments. The DoD requirement is 1.
'
  tag checktext: '
To check the minimum password age, run the command: 

$ grep PASS_MIN_DAYS /etc/login.defs

The DoD requirement is 1. 
If it is not set to the required value, this is a finding.
'

# START_CHECKS
  # describe file('/etc') do
  #  it { should be_directory }
  #end
# END_CHECKS
end
