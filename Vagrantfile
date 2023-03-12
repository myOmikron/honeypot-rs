Vagrant.configure("2") do |config|
  config.nfs.functional = false
  config.vm.synced_folder "./", "/vagrant", type: "virtiofs"

  config.vm.define "honeypot", primary: true do |honeypot|
    honeypot.vm.hostname = "honeypot"
    honeypot.vm.box = "generic/debian11"
    honeypot.vm.network "forwarded_port", guest: 80, host: 8081
    honeypot.vm.network :private_network, :ip => '10.13.37.10'
    honeypot.vm.provider "libvirt" do |vb|
        vb.memory = "2048"
        vb.cpus = "8"
        vb.memorybacking :access, :mode => "shared"
    end
    honeypot.vm.provision :ansible do |a|
      a.playbook = "vagrant/honeypot-rs.yml"
    end
  end
end