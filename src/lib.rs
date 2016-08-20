use std::fs::{File,OpenOptions};
use std::default::Default;
use std::os::unix::io::AsRawFd;
use libc::{socket,AF_INET,AF_INET6,SOCK_DGRAM,c_char,c_ulong,c_ushort,c_int};
use libc::{sockaddr_in,sockaddr,in_addr,in6_addr};
use std::io::{Read,Write,Result,Error};
use std::ffi::CString;

//use std::sync::mpsc::{channel,Sender,Receiver};
//use std::thread;
use std::mem;

#[macro_use]
extern crate bitflags;
extern crate log;
extern crate libc;

const IFNAMSIZ: usize = 16;

#[repr(C)]
struct InterfaceRequest16 {
	name: [u8; IFNAMSIZ],
	flags: c_ushort,
}

#[repr(C)]
struct InterfaceRequest32 {
	name: [u8; IFNAMSIZ],
	flags: c_int,
}

#[repr(C)]
struct InterfaceRequestSockaddrIn {
	name: [u8; IFNAMSIZ],
	sockaddr: sockaddr_in,
}

#[repr(C)]
struct InterfaceRequestSockaddr {
	name: [u8; IFNAMSIZ],
	sockaddr: sockaddr,
}

#[repr(C)]
struct InterfaceRequestIn6 {
	addr:      in6_addr,
	prefixlen: u32,
	ifindex:   c_int,
}

impl Default for InterfaceRequest16 {
	fn default() -> InterfaceRequest16 {
		InterfaceRequest16 {
			name: [0; IFNAMSIZ],
			flags: 0,
		}		
	}
}

impl Default for InterfaceRequest32 {
	fn default() -> InterfaceRequest32 {
		InterfaceRequest32 {
			name: [0; IFNAMSIZ],
			flags: 0,
		}		
	}
}

impl Default for InterfaceRequestSockaddrIn {
	fn default() -> InterfaceRequestSockaddrIn {
		InterfaceRequestSockaddrIn {
			name: [0; IFNAMSIZ],
			sockaddr: sockaddr_in {
				sin_family: 0,
				sin_port:   0,
				sin_addr:   in_addr {
					s_addr: 0
				},
				sin_zero:   [0;8],
			}
		}		
	}
}

impl Default for InterfaceRequestSockaddr {
	fn default() -> InterfaceRequestSockaddr {
		InterfaceRequestSockaddr {
			name: [0; IFNAMSIZ],
			sockaddr: sockaddr {
				sa_family: 0,
				sa_data:   [0;14]
			}
		}		
	}
}

pub type Uid = u32;
pub type Gid = u32;

extern "C" {
	fn ioctl(fd: i32, icr: IoCtlRequest, some: c_ulong) -> i32;
	fn inet_pton(af: c_int, src: *const c_char, dst: &mut in_addr) -> c_int;
}

bitflags! {
	pub flags TunTapFlags: u16 {
		const IFF_UP        = 1<<0,
		const IFF_RUNNING   = 1<<6,
		const IFF_TUN       = 0x0001,
		const IFF_TAP       = 0x0002,
		const IFF_NO_PI     = 0x0100,
		const IFF_ONE_QUEUE = 0x0200,
		const IFF_VNET_HDR  = 0x0400,
		const IFF_TUN_EXCL  = 0x0800,
	}
}

bitflags! {
	#[repr(C)]
	flags IoCtlRequest: u32 {
		const TUNSETIFF      = 0x400454ca,
		const TUNSETOWNER    = 0x400454cc,
		const TUNSETGROUP    = 0x400454ce,

		const SIOCGIFFLAGS   = 0x8913,
		const SIOCSIFFLAGS   = 0x8914,
		const SIOCSIFADDR    = 0x8916,
		const SIOCSIFMTU     = 0x8922,
		const SIOCSIFNAME    = 0x8923,
		const SIOCSIFHWADDR  = 0x8924,
		const SIOCGIFINDEX   = 0x8933,
		const SIOGIFINDEX    = 0x8933, // same as SIOCGIFINDEX
	}
}

//#[derive(Copy,Clone)]
pub struct TunTap {
	//fd:   RawFd,
    file: File,
	sock4: c_int,
	sock6: c_int,
	name: [u8; IFNAMSIZ],
}

macro_rules! ioctl(
	($fd:expr, $flags:expr, $value:expr) => ({
		let ptr = mem::transmute($value);
		let res = ioctl($fd, $flags, ptr);

		if res < 0 {
			Err(Error::last_os_error())
		} else {
			Ok(())
		}
	})
);

impl TunTap {
	pub fn new(flags: TunTapFlags, name: &'static str)
		-> Result<TunTap>
	{
		let file = OpenOptions::new().read(true).write(true).open("/dev/net/tun").unwrap();

		let mut ifr_create = InterfaceRequest16 {
			flags: flags.bits(),
			..Default::default()
		};
		ifr_create.name[0..name.len()].copy_from_slice(&String::from(name).as_bytes());
		let create = unsafe { ioctl!(file.as_raw_fd(), TUNSETIFF, &ifr_create) };
		if create.is_err() {
			return Err(create.unwrap_err());
		}

		const IPPROTO_IP: c_int = 0;
		let sock4 = unsafe { socket(AF_INET, SOCK_DGRAM, IPPROTO_IP) };
		if sock4 < 0 {
			return Err(Error::last_os_error())
		}

		let sock6 = unsafe { socket(AF_INET6, SOCK_DGRAM, 0) };
		if sock6 < 0 {
			return Err(Error::last_os_error())
		}

		//let fd = file.as_raw_fd(); //unsafe { dup(self.file.as_raw_fd()) };
		let tuntap = TunTap {
			//fd: fd,
            file: file,
			sock4: sock4,
			sock6: sock6,
			name: ifr_create.name,
		};

        Ok(tuntap)
    }

    pub fn send(&mut self, data: Vec<u8>) -> Result<usize> {
        self.file.write(data.as_slice())
    }

    pub fn recv(&mut self) -> Vec<u8> {
        let mut packet = Vec::with_capacity(2048);
        match self.file.read(&mut packet) {
            Ok(sz) => packet[0..sz].to_vec(),
            _ => vec![]
        }
    }

	pub fn set_owner(&self, owner: Uid) -> Result<()> {
		unsafe { ioctl!(self.file.as_raw_fd(), TUNSETOWNER, owner as u64) }
	}

	pub fn set_group(&self, group: Gid) -> Result<()> {
		unsafe { ioctl!(self.file.as_raw_fd(), TUNSETGROUP, group as u64) }
	}

	pub fn set_mtu(&self, mtu: i32) -> Result<()> {
		let ifr = InterfaceRequest32 {
			name: self.name,
			flags: mtu,
		};
		unsafe { ioctl!(self.sock4, SIOCSIFMTU, &ifr) }
	}

	/*
	pub fn set_mac(self, mac: [u8;6]) -> Result<()> {
		// only works on TAPs!
		// but still fails - why? TODO
		let mut ifr = InterfaceRequestSockaddr {
			name: self.name,
			..Default::default()
		};
		ifr.sockaddr.sa_family = AF_INET as c_ushort;
		for (i, b) in mac.iter().enumerate() {
			ifr.sockaddr.sa_data[i] = *b;
		}
		unsafe { ioctl!(self.sock4, SIOCSIFHWADDR, &ifr) }
	}*/

	pub fn set_ipv4(&self, ipv4: &'static str) -> Result<()> {
		let mut ifr_ipaddr = InterfaceRequestSockaddrIn {
			name:     self.name,
			..Default::default()
		};
		ifr_ipaddr.sockaddr.sin_family = AF_INET as c_ushort;
		let ip = CString::new(ipv4.as_bytes()).unwrap();
		let res = unsafe { inet_pton(AF_INET, ip.as_ptr(),
								&mut ifr_ipaddr.sockaddr.sin_addr) == 1 };
		if !res {
			return Err(Error::last_os_error());
		}

		unsafe { ioctl!(self.sock4, SIOCSIFADDR, &ifr_ipaddr) }
	}

	pub fn set_ipv6(&self, ipv6: &'static str) -> Result<()> {
		let mut ifr = InterfaceRequest32 {
			name: self.name,
			..Default::default()
		};
		let res = unsafe { ioctl!(self.sock6, SIOGIFINDEX, &mut ifr) };
		if res.is_err() {
			return Err(res.unwrap_err());
		}

		// Can't do in6_addr{ } because it has a private member you can't init
		let i6addr: in6_addr = unsafe { mem::uninitialized() };
		//i6addr.s6_addr = [0, 16];
		let mut ifr6 = InterfaceRequestIn6 {
			addr:      i6addr,
			prefixlen: 64,
			ifindex:   ifr.flags,
		};

		let ip = CString::new(ipv6.as_bytes()).unwrap();
		let res = unsafe { inet_pton(AF_INET6, ip.as_ptr(),
								::std::mem::transmute(&mut (ifr6.addr.s6_addr))) == 1 };
		if !res {
			return Err(Error::last_os_error());
		}
		unsafe { ioctl!(self.sock6, SIOCSIFADDR, &ifr6) }
	}

	pub fn set_up(&self) -> Result<()> {
		let mut ifr_setup = InterfaceRequest16 {
			name: self.name,
			..Default::default()
		};
		let setup = unsafe { ioctl!(self.sock4, SIOCGIFFLAGS, &ifr_setup) };
		if setup.is_err() {
			return Err(setup.unwrap_err());
		}

		ifr_setup.flags |= (IFF_UP | IFF_RUNNING).bits();
		unsafe { ioctl!(self.sock4, SIOCSIFFLAGS, &ifr_setup) }
	}
}
