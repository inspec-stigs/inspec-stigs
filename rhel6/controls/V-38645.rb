# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38645 - The system default umask in /etc/login.defs must be 077.'

control 'V-38645' do
  impact 0.1
  title 'The system default umask in /etc/login.defs must be 077.'
  desc '
The umask value influences the permissions assigned to files when they are created. A misconfigured umask value could result in files with excessive permissions that can be read and/or written to by unauthorized users.
'
  tag 'stig','V-38645'
  tag severity: 'low'
  tag checkid: 'C-46205r1_chk'
  tag fixid: 'F-43594r1_fix'
  tag version: 'RHEL-06-000345'
  tag ruleid: 'SV-50446r1_rule'
  tag fixtext: '
To ensure the default umask controlled by "/etc/login.defs" is set properly, add or correct the "umask" setting in "/etc/login.defs" to read as follows:

UMASK 077
'
  tag checktext: '
Verify the "umask" setting is configured correctly in the "/etc/login.defs" file by running the following command:

# grep -i "umask" /etc/login.defs

All output must show the value of "umask" set to 077, as shown in the below:

# grep -i "umask" /etc/login.defs
UMASK 077


If the above command returns no output, or if the umask is configured incorrectly, this is a finding.
'

# START_DESCRIBE V-38645
  tag 'login.defs','UMASK'
  describe login_defs do
    its('UMASK') { should eq '077' }
  end

# END_DESCRIBE V-38645

end
