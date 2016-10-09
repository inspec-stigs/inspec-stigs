# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38608 - The SSH daemon must set a timeout interval on idle sessions.'

control 'V-38608' do
  impact 0.1
  title 'The SSH daemon must set a timeout interval on idle sessions.'
  desc '
Causing idle users to be automatically logged out guards against compromises one system leading trivially to compromises on another.
'
  tag 'stig','V-38608'
  tag severity: 'low'
  tag checkid: 'C-46167r1_chk'
  tag fixid: 'F-43556r1_fix'
  tag version: 'RHEL-06-000230'
  tag ruleid: 'SV-50409r1_rule'
  tag fixtext: '
SSH allows administrators to set an idle timeout interval. After this interval has passed, the idle user will be automatically logged out.

To set an idle timeout interval, edit the following line in "/etc/ssh/sshd_config" as follows:

ClientAliveInterval [interval]

The timeout [interval] is given in seconds. To have a timeout of 15 minutes, set [interval] to 900.

If a shorter timeout has already been set for the login shell, that value will preempt any SSH setting made here. Keep in mind that some processes may stop SSH from correctly detecting that the user is idle.
'
  tag checktext: '
Run the following command to see what the timeout interval is:

# grep ClientAliveInterval /etc/ssh/sshd_config

If properly configured, the output should be:

ClientAliveInterval 900


If it is not, this is a finding.
'

# START_DESCRIBE V-38608
  tag 'sshd','ClientAliveInterval'
  describe sshd_config do
    its('ClientAliveInterval') { should eq '900' }
  end
# END_DESCRIBE V-38608

end
