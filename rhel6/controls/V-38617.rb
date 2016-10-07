# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38617 - The SSH daemon must be configured to use only FIPS 140-2 approved ciphers.'

control 'V-38617' do
  impact 0.5
  title 'The SSH daemon must be configured to use only FIPS 140-2 approved ciphers.'
  desc '
Approved algorithms should impart some level of confidence in their implementation. These are also required for compliance.
'
  tag 'stig','V-38617'
  tag severity: 'medium'
  tag checkid: 'C-46176r1_chk'
  tag fixid: 'F-43566r1_fix'
  tag version: 'RHEL-06-000243'
  tag ruleid: 'SV-50418r1_rule'
  tag fixtext: '
Limit the ciphers to those algorithms which are FIPS-approved. Counter (CTR) mode is also preferred over cipher-block chaining (CBC) mode. The following line in "/etc/ssh/sshd_config" demonstrates use of FIPS-approved ciphers: 

Ciphers aes128-ctr,aes192-ctr,aes256-ctr,aes128-cbc,3des-cbc,aes192-cbc,aes256-cbc

The man page "sshd_config(5)" contains a list of supported ciphers.
'
  tag checktext: '
Only FIPS-approved ciphers should be used. To verify that only FIPS-approved ciphers are in use, run the following command: 

# grep Ciphers /etc/ssh/sshd_config

The output should contain only those ciphers which are FIPS-approved, namely, the AES and 3DES ciphers. 
If that is not the case, this is a finding.
'

# START_CHECKS
  # describe file('/etc') do
  #  it { should be_directory }
  #end
# END_CHECKS
end
