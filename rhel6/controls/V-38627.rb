# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38627 - The openldap-servers package must not be installed unless required.'

control 'V-38627' do
  impact 0.1
  title 'The openldap-servers package must not be installed unless required.'
  desc '
Unnecessary packages should not be installed to decrease the attack surface of the system.
'
  tag 'stig','V-38627'
  tag severity: 'low'
  tag checkid: 'C-46187r1_chk'
  tag fixid: 'F-43577r1_fix'
  tag version: 'RHEL-06-000256'
  tag ruleid: 'SV-50428r1_rule'
  tag fixtext: '
The "openldap-servers" package should be removed if not in use. Is this machine the OpenLDAP server? If not, remove the package.

# yum erase openldap-servers

The openldap-servers RPM is not installed by default on RHEL6 machines. It is needed only by the OpenLDAP server, not by the clients which use LDAP for authentication. If the system is not intended for use as an LDAP Server it should be removed.
'
  tag checktext: '
To verify the "openldap-servers" package is not installed, run the following command:

$ rpm -q openldap-servers

The output should show the following.

package openldap-servers is not installed


If it does not, this is a finding.
'

# START_DESCRIBE V-38627
  tag 'openldap-servers','package'
  describe package('openldap-servers') do
    it { should_not be_installed }
  end
# END_DESCRIBE V-38627

end
