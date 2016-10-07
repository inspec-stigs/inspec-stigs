# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38629 - The graphical desktop environment must set the idle timeout to no more than 15 minutes.'

control 'V-38629' do
  impact 0.5
  title 'The graphical desktop environment must set the idle timeout to no more than 15 minutes.'
  desc '
Setting the idle delay controls when the screensaver will start, and can be combined with screen locking to prevent access from passersby.
'
  tag 'stig','V-38629'
  tag severity: 'medium'
  tag checkid: 'C-46188r3_chk'
  tag fixid: 'F-43578r1_fix'
  tag version: 'RHEL-06-000257'
  tag ruleid: 'SV-50430r3_rule'
  tag fixtext: '
Run the following command to set the idle time-out value for inactivity in the GNOME desktop to 15 minutes: 

# gconftool-2 \
--direct \
--config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory \
--type int \
--set /apps/gnome-screensaver/idle_delay 15
'
  tag checktext: '
If the GConf2 package is not installed, this is not applicable.

To check the current idle time-out value, run the following command: 

$ gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --get /apps/gnome-screensaver/idle_delay

If properly configured, the output should be "15". 

If it is not, this is a finding.
'

# START_CHECKS
  # describe file('/etc') do
  #  it { should be_directory }
  #end
# END_CHECKS
end
