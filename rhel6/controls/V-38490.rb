# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38490 - The operating system must enforce requirements for the connection of mobile devices to operating systems.'

control 'V-38490' do
  impact 0.5
  title 'The operating system must enforce requirements for the connection of mobile devices to operating systems.'
  desc '
USB storage devices such as thumb drives can be used to introduce unauthorized software and other vulnerabilities. Support for these devices should be disabled and the devices themselves should be tightly controlled.
'
  tag 'stig','V-38490'
  tag severity: 'medium'
  tag checkid: 'C-46047r3_chk'
  tag fixid: 'F-43437r3_fix'
  tag version: 'RHEL-06-000503'
  tag ruleid: 'SV-50291r4_rule'
  tag fixtext: '
To prevent USB storage devices from being used, configure the kernel module loading system to prevent automatic loading of the USB storage driver. To configure the system to prevent the "usb-storage" kernel module from being loaded, add the following line to a file in the directory "/etc/modprobe.d":

install usb-storage /bin/true

This will prevent the "modprobe" program from loading the "usb-storage" module, but will not prevent an administrator (or another program) from using the "insmod" program to load the module manually.
'
  tag checktext: '
If the system is configured to prevent the loading of the "usb-storage" kernel module, it will contain lines inside any file in "/etc/modprobe.d" or the deprecated"/etc/modprobe.conf". These lines instruct the module loading system to run another program (such as "/bin/true") upon a module "install" event. Run the following command to search for such lines in all files in "/etc/modprobe.d" and the deprecated "/etc/modprobe.conf":

$ grep -r usb-storage /etc/modprobe.conf /etc/modprobe.d

If no line is returned, this is a finding.
'

# START_DESCRIBE V-38490
  describe kernel_module('usb-storage') do
    it { should_not be_loaded }
  end
  if file('/etc/modprobe.conf').exist?
    check_files = '/etc/modprobe.conf /etc/modprobe.d'
  else
    check_files = '/etc/modprobe.d'
  end
  describe command("grep -r 'install usb-storage /bin/true' #{check_files}") do
    its('stdout') { should_not eq '' }
  end
# END_DESCRIBE V-38490

end
