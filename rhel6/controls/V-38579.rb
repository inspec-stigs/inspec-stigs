# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38579 - The system boot loader configuration file(s) must be owned by root.'

control 'V-38579' do
  impact 0.5
  title 'The system boot loader configuration file(s) must be owned by root.'
  desc '
Only root should be able to modify important boot parameters.
'
  tag 'stig','V-38579'
  tag severity: 'medium'
  tag checkid: 'C-46137r1_chk'
  tag fixid: 'F-43527r1_fix'
  tag version: 'RHEL-06-000065'
  tag ruleid: 'SV-50380r1_rule'
  tag fixtext: '
The file "/etc/grub.conf" should be owned by the "root" user to prevent destruction or modification of the file. To properly set the owner of "/etc/grub.conf", run the command:

# chown root /etc/grub.conf
'
  tag checktext: '
To check the ownership of "/etc/grub.conf", run the command:

$ ls -lL /etc/grub.conf

If properly configured, the output should indicate the following owner: "root"
If it does not, this is a finding.
'

# START_DESCRIBE V-38579
  describe file('/etc/grub.conf') do
    its('owner') { should eq 'root' }
  end
# END_DESCRIBE V-38579

end
