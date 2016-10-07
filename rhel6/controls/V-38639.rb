# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38639 - The system must display a publicly-viewable pattern during a graphical desktop environment session lock.'

control 'V-38639' do
  impact 0.1
  title 'The system must display a publicly-viewable pattern during a graphical desktop environment session lock.'
  desc '
Setting the screensaver mode to blank-only conceals the contents of the display from passersby.
'
  tag 'stig','V-38639'
  tag severity: 'low'
  tag checkid: 'C-46199r4_chk'
  tag fixid: 'F-43588r2_fix'
  tag version: 'RHEL-06-000260'
  tag ruleid: 'SV-50440r3_rule'
  tag fixtext: '
Run the following command to set the screensaver mode in the GNOME desktop to a blank screen: 

# gconftool-2 \
--direct \
--config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory \
--type string \
--set /apps/gnome-screensaver/mode blank-only
'
  tag checktext: '
If the GConf2 package is not installed, this is not applicable. 

To ensure the screensaver is configured to be blank, run the following command: 

$ gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --get /apps/gnome-screensaver/mode

If properly configured, the output should be "blank-only". 
If it is not, this is a finding.
'

# START_CHECKS
  # describe file('/etc') do
  #  it { should be_directory }
  #end
# END_CHECKS
end
