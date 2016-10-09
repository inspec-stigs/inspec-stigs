# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure(2) do |config|
  config.vm.box = "centos/6"
  config.vm.synced_folder ".", "/vagrant", type: "nfs"
  config.vm.network :private_network, ip: "172.16.0.100"
  config.vm.provision "shell", inline: <<-SHELL

    if [ ! -e /vagrant/inspec.rpm ]; then
      sudo yum install -y wget
      wget -q -O /vagrant/inspec.rpm https://packages.chef.io/stable/el/6/inspec-1.0.0-1.el6.x86_64.rpm
     fi
      sudo rpm -i /vagrant/inspec.rpm || echo .
  SHELL
end
