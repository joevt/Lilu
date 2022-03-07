onevar(vm_object_t, compressor_object)
onevar(int, cs_process_enforcement_enable)
onevar(uint64_t, physmap_base)
onevar(uint64_t, physmap_max)
onevar(boolean_t, no_shared_cr3)
onevar(boolean_t, pmap_smap_enabled)
onevar(uint32_t, pmap_pcid_ncpus)
//onevar(int, panic_on_unsigned_execute)
//onevar(bool, zalloc_disable_copyio_check)
//onevar(copyout_shim_fn_t, copyout_shim_fn)
//onevar(unsigned, co_src_flags)
//onevar(struct vnode, rootvnode)

oneproc(int, override_nx, (_vm_map* map, uint32_t user_tag))
oneproc(bool, pmap_has_prot_policy, (pmap_t pmap, bool translated_allow_execute, vm_prot_t prot))
oneproc(void, pmap_protect, (pmap_t map, vm_map_offset_t s, vm_map_offset_t e, vm_prot_t prot))
oneproc(void, pmap_protect_options, (pmap_t map, vm_map_offset_t s, vm_map_offset_t e, vm_prot_t prot, unsigned int options, void *arg))
oneproc(char *, proc_name_address, (void *p))
oneproc(uint64_t, proc_selfcsflags, ())
oneproc(void, vm_map_clip_end, (_vm_map* map, vm_map_entry_t entry, vm_map_offset_t endaddr))
oneproc(void, vm_map_clip_start, (_vm_map* map, vm_map_entry_t  entry, vm_map_offset_t endaddr))
oneproc(boolean_t, vm_map_lookup_entry, (_vm_map_t map, vm_map_address_t address, vm_map_entry_t *entry))
oneproc(void, vm_map_simplify_entry, (_vm_map_t map, vm_map_entry_t this_entry))
oneproc(kern_return_t, vm_map_remap, (
	_vm_map_t               target_map,
	vm_map_offset_t         *address,
	vm_map_size_t           size,
	vm_map_offset_t         mask,
	int                     flags,
	vm_map_kernel_flags_t   vmk_flags,
	vm_tag_t                tag,
	vm_map_t                src_map,
	vm_map_offset_t         memory_address,
	boolean_t               copy,
	vm_prot_t               *cur_protection,
	vm_prot_t               *max_protection,
	vm_inherit_t            inheritance))

oneproc(int, _bcopy, (const void *, void *, vm_size_t))
oneproc(int, _bcopystr, (const void *, void *, vm_size_t, vm_size_t *))
oneproc(int, _copyin_atomic32, (const void *src, void *dst))
oneproc(int, _copyin_atomic64, (const void *src, void *dst))
oneproc(int, _copyout_atomic32, (const void *u32, void *src))
oneproc(int, _copyout_atomic64, (const void *u64, void *src))
oneproc(vm_map_t, current_map, (void))
oneproc(vm_map_t, vm_map_switch, (vm_map_t map))
//oneproc(vm_size_t, zone_element_size, (void *addr, zone_t *z))
oneproc(void, pmap_pcid_activate, (pmap_t, int, boolean_t, boolean_t))
oneproc(void, vm_map_reference, (vm_map_t map))

#undef onevar
#undef oneproc
