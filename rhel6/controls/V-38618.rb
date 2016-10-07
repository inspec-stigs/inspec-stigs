# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38618 - The avahi service must be disabled.'

control 'V-38618' do
  impact 0.1
  title 'The avahi service must be disabled.'
  desc '
Because the Avahi daemon service keeps an open network port, it is subject to network attacks. Its functionality is convenient but is only appropriate if the local network can be trusted.
'
  tag 'stig','V-38618'
  tag severity: 'low'
  tag checkid: 'C-46177r1_chk'
  tag fixid: 'F-43567r2_fix'
  tag version: 'RHEL-06-000246'
  tag ruleid: 'SV-50419r2_rule'
  tag fixtext: '
The "avahi-daemon" service can be disabled with the following commands: 

# chkconfig avahi-daemon off
# service avahi-daemon stop
'
  tag checktext: '
To check that the "avahi-daemon" service is disabled in system boot configuration, run the following command: 

# chkconfig "avahi-daemon" --list

Output should indicate the "avahi-daemon" service has either not been installed, or has been disabled at all runlevels, as shown in the example below: 

# chkconfig "avahi-daemon" --list
"avahi-daemon" 0:off 1:off 2:off 3:off 4:off 5:off 6:off

Run the following command to verify "avahi-daemon" is disabled through current runtime configuration: 

# service avahi-daemon status

If the service is disabled the command will return the following output: 

avahi-daemon is stopped


If the service is running, this is a finding.
'

# START_CHECKS
  # describe file('/etc') do
  #  it { should be_directory }
  #end
# END_CHECKS
end
