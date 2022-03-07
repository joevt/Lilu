//
//  kern_test.hpp
//  Lilu
//
//  Created by joevt on 2022-03-03.
//

#ifndef kern_test_hpp
#define kern_test_hpp

#include <mach/vm_map.h>
#include <Headers/kern_api.hpp>

void get_kernel_externals(KernelPatcher &patcher);

extern "C" {

kern_return_t
test_vm_protect(
	vm_map_t                map,
	vm_offset_t             start,
	vm_size_t               size,
	boolean_t               set_maximum,
	vm_prot_t               new_protection);

kern_return_t
test_vm_map_write_user(
	vm_map_t                map,
	void                    *src_p,
	vm_map_address_t        dst_addr,
	vm_size_t               size);

}

#endif /* kern_test_hpp */
