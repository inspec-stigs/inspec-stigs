# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38577 - The system must use a FIPS 140-2 approved cryptographic hashing algorithm for generating account password hashes (libuser.conf).'

control 'V-38577' do
  impact 0.5
  title 'The system must use a FIPS 140-2 approved cryptographic hashing algorithm for generating account password hashes (libuser.conf).'
  desc '
Using a stronger hashing algorithm makes password cracking attacks more difficult.
'
  tag 'stig','V-38577'
  tag severity: 'medium'
  tag checkid: 'C-46135r1_chk'
  tag fixid: 'F-43525r1_fix'
  tag version: 'RHEL-06-000064'
  tag ruleid: 'SV-50378r1_rule'
  tag fixtext: '
In "/etc/libuser.conf", add or correct the following line in its "[defaults]" section to ensure the system will use the SHA-512 algorithm for password hashing: 

crypt_style = sha512
'
  tag checktext: '
Inspect "/etc/libuser.conf" and ensure the following line appears in the "[default]" section: 

crypt_style = sha512


If it does not, this is a finding.
'

# START_CHECKS
  # describe file('/etc') do
  #  it { should be_directory }
  #end
# END_CHECKS
end
