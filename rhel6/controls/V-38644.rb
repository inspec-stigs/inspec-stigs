# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38644 - The ntpdate service must not be running.'

control 'V-38644' do
  impact 0.1
  title 'The ntpdate service must not be running.'
  desc '
The "ntpdate" service may only be suitable for systems which are rebooted frequently enough that clock drift does not cause problems between reboots. In any event, the functionality of the ntpdate service is now available in the ntpd program and should be considered deprecated.
'
  tag 'stig','V-38644'
  tag severity: 'low'
  tag checkid: 'C-46204r1_chk'
  tag fixid: 'F-43593r2_fix'
  tag version: 'RHEL-06-000265'
  tag ruleid: 'SV-50445r2_rule'
  tag fixtext: '
The ntpdate service sets the local hardware clock by polling NTP servers when the system boots. It synchronizes to the NTP servers listed in "/etc/ntp/step-tickers" or "/etc/ntp.conf" and then sets the local hardware clock to the newly synchronized system time. The "ntpdate" service can be disabled with the following commands: 

# chkconfig ntpdate off
# service ntpdate stop
'
  tag checktext: '
To check that the "ntpdate" service is disabled in system boot configuration, run the following command: 

# chkconfig "ntpdate" --list

Output should indicate the "ntpdate" service has either not been installed, or has been disabled at all runlevels, as shown in the example below: 

# chkconfig "ntpdate" --list
"ntpdate" 0:off 1:off 2:off 3:off 4:off 5:off 6:off

Run the following command to verify "ntpdate" is disabled through current runtime configuration: 

# service ntpdate status

If the service is disabled the command will return the following output: 

ntpdate is stopped


If the service is running, this is a finding.
'

# START_CHECKS
  # describe file('/etc') do
  #  it { should be_directory }
  #end
# END_CHECKS
end
