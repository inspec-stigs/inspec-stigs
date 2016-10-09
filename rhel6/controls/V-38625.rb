# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38625 - If the system is using LDAP for authentication or account information, the system must use a TLS connection using FIPS 140-2 approved cryptographic algorithms.'

control 'V-38625' do
  impact 0.5
  title 'If the system is using LDAP for authentication or account information, the system must use a TLS connection using FIPS 140-2 approved cryptographic algorithms.'
  desc '
The ssl directive specifies whether to use ssl or not. If not specified it will default to "no". It should be set to "start_tls" rather than doing LDAP over SSL.
'
  tag 'stig','V-38625'
  tag severity: 'medium'
  tag checkid: 'C-46184r1_chk'
  tag fixid: 'F-43574r1_fix'
  tag version: 'RHEL-06-000252'
  tag ruleid: 'SV-50426r1_rule'
  tag fixtext: '
Configure LDAP to enforce TLS use. First, edit the file "/etc/pam_ldap.conf", and add or correct the following lines:

ssl start_tls

Then review the LDAP server and ensure TLS has been configured.
'
  tag checktext: '
If the system does not use LDAP for authentication or account information, this is not applicable.

To ensure LDAP is configured to use TLS for all transactions, run the following command:

$ grep start_tls /etc/pam_ldap.conf


If no lines are returned, this is a finding.
'

# START_DESCRIBE V-38625
  tag 'pam','ldap','pam_ldap.conf'
  only_if { file('/etc/pam_ldap.conf').exist? }
  options = {
    assignment_re: /^(.*?)\s+(.*)$/
  }
  describe parse_config_file('/etc/pam_ldap.conf',options) do
    its('ssl') { should eq 'start_tls' }
  end
# END_DESCRIBE V-38625

end
