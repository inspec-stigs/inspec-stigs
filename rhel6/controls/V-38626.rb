# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38626 - The LDAP client must use a TLS connection using trust certificates signed by the site CA.'

control 'V-38626' do
  impact 0.5
  title 'The LDAP client must use a TLS connection using trust certificates signed by the site CA.'
  desc '
The tls_cacertdir or tls_cacertfile directives are required when tls_checkpeer is configured (which is the default for openldap versions 2.1 and up). These directives define the path to the trust certificates signed by the site CA.
'
  tag 'stig','V-38626'
  tag severity: 'medium'
  tag checkid: 'C-46185r1_chk'
  tag fixid: 'F-43575r1_fix'
  tag version: 'RHEL-06-000253'
  tag ruleid: 'SV-50427r1_rule'
  tag fixtext: '
Ensure a copy of the site\'s CA certificate has been placed in the file "/etc/pki/tls/CA/cacert.pem". Configure LDAP to enforce TLS use and to trust certificates signed by the site\'s CA. First, edit the file "/etc/pam_ldap.conf", and add or correct either of the following lines:

tls_cacertdir /etc/pki/tls/CA

or

tls_cacertfile /etc/pki/tls/CA/cacert.pem

Then review the LDAP server and ensure TLS has been configured.
'
  tag checktext: '
If the system does not use LDAP for authentication or account information, this is not applicable.

To ensure TLS is configured with trust certificates, run the following command:

# grep cert /etc/pam_ldap.conf


If there is no output, or the lines are commented out, this is a finding.
'

# START_DESCRIBE V-38626
  tag 'pam','ldap','pam_ldap.conf'
  only_if { file('/etc/pam_ldap.conf').exist? }
  options = {
    assignment_re: /^(.*?)\s+(.*)$/
  }
  describe.one do
    describe parse_config_file('/etc/pam_ldap.conf',options) do
      its('tls_cacertdir') { should eq '/etc/pki/tls/CA' }
    end
    describe parse_config_file('/etc/pam_ldap.conf',options) do
      its('tls_cacertfile') { should eq '/etc/pki/tls/CA/cacert.pem' }
    end
  end


# END_DESCRIBE V-38626

end
