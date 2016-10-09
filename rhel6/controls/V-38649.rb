# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38649 - The system default umask for the csh shell must be 077.'

control 'V-38649' do
  impact 0.1
  title 'The system default umask for the csh shell must be 077.'
  desc '
The umask value influences the permissions assigned to files when they are created. A misconfigured umask value could result in files with excessive permissions that can be read and/or written to by unauthorized users.
'
  tag 'stig','V-38649'
  tag severity: 'low'
  tag checkid: 'C-46209r1_chk'
  tag fixid: 'F-43598r1_fix'
  tag version: 'RHEL-06-000343'
  tag ruleid: 'SV-50450r1_rule'
  tag fixtext: '
To ensure the default umask for users of the C shell is set properly, add or correct the "umask" setting in "/etc/csh.cshrc" to read as follows:

umask 077
'
  tag checktext: '
Verify the "umask" setting is configured correctly in the "/etc/csh.cshrc" file by running the following command:

# grep "umask" /etc/csh.cshrc

All output must show the value of "umask" set to 077, as shown in the below:

# grep "umask" /etc/csh.cshrc
umask 077


If the above command returns no output, or if the umask is configured incorrectly, this is a finding.
'

# START_DESCRIBE V-38649
  tag 'csh.cshrc','umask'
  describe command("grep 'umask [0-9]' /etc/csh.cshrc | grep -v 077") do
    its('stdout') { should be '' }
  end
# END_DESCRIBE V-38649

end
