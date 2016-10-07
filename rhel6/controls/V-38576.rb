# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38576 - The system must use a FIPS 140-2 approved cryptographic hashing algorithm for generating account password hashes (login.defs).'

control 'V-38576' do
  impact 0.5
  title 'The system must use a FIPS 140-2 approved cryptographic hashing algorithm for generating account password hashes (login.defs).'
  desc '
Using a stronger hashing algorithm makes password cracking attacks more difficult.
'
  tag 'stig','V-38576'
  tag severity: 'medium'
  tag checkid: 'C-46134r1_chk'
  tag fixid: 'F-43524r1_fix'
  tag version: 'RHEL-06-000063'
  tag ruleid: 'SV-50377r1_rule'
  tag fixtext: '
In "/etc/login.defs", add or correct the following line to ensure the system will use SHA-512 as the hashing algorithm: 

ENCRYPT_METHOD SHA512
'
  tag checktext: '
Inspect "/etc/login.defs" and ensure the following line appears: 

ENCRYPT_METHOD SHA512


If it does not, this is a finding.
'

# START_CHECKS
  # describe file('/etc') do
  #  it { should be_directory }
  #end
# END_CHECKS
end
