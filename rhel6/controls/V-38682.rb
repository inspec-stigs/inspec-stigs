# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38682 - The Bluetooth kernel module must be disabled.'

control 'V-38682' do
  impact 0.5
  title 'The Bluetooth kernel module must be disabled.'
  desc '
If Bluetooth functionality must be disabled, preventing the kernel from loading the kernel module provides an additional safeguard against its activation.
'
  tag 'stig','V-38682'
  tag severity: 'medium'
  tag checkid: 'C-46244r3_chk'
  tag fixid: 'F-43631r3_fix'
  tag version: 'RHEL-06-000315'
  tag ruleid: 'SV-50483r3_rule'
  tag fixtext: '
The kernel\'s module loading system can be configured to prevent loading of the Bluetooth module. Add the following to the appropriate "/etc/modprobe.d" configuration file to prevent the loading of the Bluetooth module:

install net-pf-31 /bin/true
install bluetooth /bin/true
'
  tag checktext: '
If the system is configured to prevent the loading of the "bluetooth" kernel module, it will contain lines inside any file in "/etc/modprobe.d" or the deprecated"/etc/modprobe.conf". These lines instruct the module loading system to run another program (such as "/bin/true") upon a module "install" event. Run the following command to search for such lines in all files in "/etc/modprobe.d" and the deprecated "/etc/modprobe.conf":

$ grep -r bluetooth /etc/modprobe.conf /etc/modprobe.d

If the system is configured to prevent the loading of the "net-pf-31" kernel module, it will contain lines inside any file in "/etc/modprobe.d" or the deprecated"/etc/modprobe.conf". These lines instruct the module loading system to run another program (such as "/bin/true") upon a module "install" event. Run the following command to search for such lines in all files in "/etc/modprobe.d" and the deprecated "/etc/modprobe.conf":

$ grep -r net-pf-31 /etc/modprobe.conf /etc/modprobe.d

If no line is returned, this is a finding.
'

# START_DESCRIBE V-38682
  tag 'kernel','modprobe','bluetooth','net-pf-31'
  ['net-pf-31','bluetooth'].each do |km|
    describe kernel_module(km) do
      it { should_not be_loaded }
    end
    if file('/etc/modprobe.conf').exist?
      check_files = '/etc/modprobe.conf /etc/modprobe.d'
    else
      check_files = '/etc/modprobe.d'
    end
    describe command("grep -r 'install #{km} /bin/true' #{check_files}") do
      its('stdout') { should_not eq '' }
    end
  end
# END_DESCRIBE V-38682

end
