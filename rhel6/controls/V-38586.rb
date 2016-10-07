# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38586 - The system must require authentication upon booting into single-user and maintenance modes.'

control 'V-38586' do
  impact 0.5
  title 'The system must require authentication upon booting into single-user and maintenance modes.'
  desc '
This prevents attackers with physical access from trivially bypassing security on the machine and gaining root access. Such accesses are further prevented by configuring the bootloader password.
'
  tag 'stig','V-38586'
  tag severity: 'medium'
  tag checkid: 'C-46145r1_chk'
  tag fixid: 'F-43534r1_fix'
  tag version: 'RHEL-06-000069'
  tag ruleid: 'SV-50387r1_rule'
  tag fixtext: '
Single-user mode is intended as a system recovery method, providing a single user root access to the system by providing a boot option at startup. By default, no authentication is performed if single-user mode is selected. 

To require entry of the root password even if the system is started in single-user mode, add or correct the following line in the file "/etc/sysconfig/init": 

SINGLE=/sbin/sulogin
'
  tag checktext: '
To check if authentication is required for single-user mode, run the following command: 

$ grep SINGLE /etc/sysconfig/init

The output should be the following: 

SINGLE=/sbin/sulogin


If the output is different, this is a finding.
'

# START_CHECKS
  # describe file('/etc') do
  #  it { should be_directory }
  #end
# END_CHECKS
end
