# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38590 - The system must allow locking of the console screen in text mode.'

control 'V-38590' do
  impact 0.1
  title 'The system must allow locking of the console screen in text mode.'
  desc '
Installing "screen" ensures a console locking capability is available for users who may need to suspend console logins.
'
  tag 'stig','V-38590'
  tag severity: 'low'
  tag checkid: 'C-46148r1_chk'
  tag fixid: 'F-43538r1_fix'
  tag version: 'RHEL-06-000071'
  tag ruleid: 'SV-50391r1_rule'
  tag fixtext: '
To enable console screen locking when in text mode, install the "screen" package:

# yum install screen

Instruct users to begin new terminal sessions with the following command:

$ screen

The console can now be locked with the following key combination:

ctrl+a x
'
  tag checktext: '
Run the following command to determine if the "screen" package is installed:

# rpm -q screen


If the package is not installed, this is a finding.
'

# START_DESCRIBE V-38590
  describe package('screen') do
    it { should be_installed }
  end
# END_DESCRIBE V-38590

end
