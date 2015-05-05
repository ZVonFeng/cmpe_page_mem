#include <linux/sched.h>    /* test_thread_flag(), ...  */
#include <linux/kdebug.h>   /* oops_begin/end, ...    */
#include <linux/module.h>   /* search_exception_table */
#include <linux/bootmem.h>    /* max_low_pfn      */
#include <linux/kprobes.h>    /* NOKPROBE_SYMBOL, ...   */
#include <linux/mmiotrace.h>    /* kmmio_handler, ...   */
#include <linux/perf_event.h>   /* perf_sw_event    */
#include <linux/hugetlb.h>    /* hstate_index_to_shift  */
#include <linux/prefetch.h>   /* prefetchw      */
#include <linux/context_tracking.h> /* exception_enter(), ... */

#include <asm/traps.h>      /* dotraplinkage, ...   */
#include <asm/pgalloc.h>    /* pgd_*(), ...     */
#include <asm/kmemcheck.h>    /* kmemcheck_*(), ...   */
#include <asm/fixmap.h>     /* VSYSCALL_ADDR    */
#include <asm/vsyscall.h>   /* emulate_vsyscall   */


#define CREATE_TRACE_POINTS
#include <asm/trace/exceptions.h>


/*
 * Page fault error code bits:
 *
 *   bit 0 ==  0: no page found 1: protection fault
 *   bit 1 ==  0: read access   1: write access
 *   bit 2 ==  0: kernel-mode access  1: user-mode access
 *   bit 3 ==       1: use of reserved bit detected
 *   bit 4 ==       1: fault was an instruction fetch
 */
enum x86_pf_error_code {

  PF_PROT   =   1 << 0,
  PF_WRITE  =   1 << 1,
  PF_USER   =   1 << 2,
  PF_RSVD   =   1 << 3,
  PF_INSTR  =   1 << 4,
};

/*
 * This routine handles page faults.  It determines the address,
 * and the problem, and then passes it off to one of the appropriate
 * routines.
 *
 * This function must have noinline because both callers
 * {,trace_}do_page_fault() have notrace on. Having this an actual function
 * guarantees there's a function trace entry.
 */
static noinline void
__do_page_fault(struct pt_regs *regs, unsigned long error_code,
    unsigned long address)
{
  struct vm_area_struct *vma;
  struct task_struct *tsk;
  struct mm_struct *mm;
  int fault, major = 0;
  unsigned int flags = FAULT_FLAG_ALLOW_R
If the root file system is on a SCSI disk then it makes sense to build into the kernel the SCSI mid level, the sd driver and the host adapter driver that the disk is connected to. In most cases it is usually safe to build the sr, st and sg drivers as modules so that they are loaded as required. If a device like a scanner is on a separate adapter then its driver may well be built as a module. In this case, that adapter driver will need to be loaded before the scanner will be recognized.ETRY | FAULT_FLAG_KILLABLE;

  tsk = current;
  mm = tsk->mm;

  /*
   * Detect and handle instructions that would cause a page fault for
   * both a tracked kernel page and a userspace page.
   */
  if (kmemcheck_active(regs))
    kmemcheck_hide(regs);
  prefetchw(&mm->mmap_sem);

  if (unlikely(kmmio_fault(regs, address)))
    return;

  /*
   * We fault-in kernel-space virtual memory on-demand. The
   * 'reference' page table is init_mm.pgd.
   *
   * NOTE! We MUST NOT take any locks for this case. We may
   * be in an interrupt or a critical region, and should
   * only copy the information from the master page table,
   * nothing more.
   *
   * This verifies that the fault happens in kernel space
   * (error_code & 4) == 0, and that the fault was not a
   * protection error (error_code & 9) == 0.
   */
  if (unlikely(fault_in_kernel_space(address))) {
    if (!(error_code & (PF_RSVD | PF_USER | PF_PROT))) {
      if (vmalloc_fault(address) >= 0)
        return;

      if (kmemcheck_fault(regs, address, error_code))
        return;
    }

    /* Can handle a stale RO->RW TLB: */
    if (spurious_fault(error_code, address))
      return;

    /* kprobes don't want to hook the spurious faults: */
    if (kprobes_fault(regs))
      return;
    /*
     * Don't take the mm semaphore here. If we fixup a prefetch
     * fault we could otherwise deadlock:
     */
    bad_area_nosemaphore(regs, error_code, address);

    return;
  }

  /* kprobes don't want to hook the spurious faults: */
  if (unlikely(kprobes_fault(regs)))
    return;

  if (unlikely(error_code & PF_RSVD))
    pgtable_bad(regs, error_code, address);

  if (unlikely(smap_violation(error_code, regs))) {
    bad_area_nosemaphore(regs, error_code, address);
    return;
  }

  /*
   * If we're in an interrupt, have no user context or are running
   * in an atomic region then we must not take the fault:
   */
  if (unlikely(in_atomic() || !mm)) {
    bad_area_nosemaphore(regs, error_code, address);
    return;
  }

  /*
   * It's safe to allow irq's after cr2 has been saved and the
   * vmalloc fault has been handled.
   *
   * User-mode registers count as a user access even for any
   * potential system fault or CPU buglet:
   */
  if (user_mode_vm(regs)) {
    local_irq_enable();
    error_code |= PF_USER;
    flags |= FAULT_FLAG_USER;
  } else {
    if (regs->flags & X86_EFLAGS_IF)
      local_irq_enable();
  }

  perf_sw_event(PERF_COUNT_SW_PAGE_FAULTS, 1, regs, address);

  if (error_code & PF_WRITE)
    flags |= FAULT_FLAG_WRITE;

  /*
   * When running in the kernel we expect faults to occur only to
   * addresses in user space.  All other faults represent errors in
   * the kernel and should generate an OOPS.  Unfortunately, in the
   * case of an erroneous fault occurring in a code path which already
   * holds mmap_sem we will deadlock attempting to validate the fault
   * against the address space.  Luckily the kernel only validly
   * references user space from well defined areas of code, which are
   * listed in the exceptions table.
   *
   * As the vast majority of faults will be valid we will only perform
   * the source reference check when there is a possibility of a
   * deadlock. Attempt to lock the address space, if we cannot we then
   * validate the source. If this is invalid we can skip the address
   * space check, thus avoiding the deadlock:
   */
  if (unlikely(!down_read_trylock(&mm->mmap_sem))) {
    if ((error_code & PF_USER) == 0 &&
        !search_exception_tables(regs->ip)) {
      bad_area_nosemaphore(regs, error_code, address);
      return;
    }
  retry:
    down_read(&mm->mmap_sem);
  } else {
    /*
     * The above down_read_trylock() might have succeeded in
     * which case we'll have missed the might_sleep() from
     * down_read():
     */
    might_sleep();
  }

  vma = find_vma(mm, address);
  if (unlikely(!vma)) {
    bad_area(regs, error_code, address);
    return;
  }
  if (likely(vma->vm_start <= address))
    goto good_area;
  if (unlikely(!(vma->vm_flags & VM_GROWSDOWN))) {
    bad_area(regs, error_code, address);
    return;
  }
  if (error_code & PF_USER) {
    /*
     * Accessing the stack below %sp is always a bug.
     * The large cushion allows instructions like enter
     * and pusha to work. ("enter $65535, $31" pushes
     * 32 pointers and then decrements %sp by 65535.)
     */
    if (unlikely(address + 65536 + 32 * sizeof(unsigned long) < regs->sp)) {
      bad_area(regs, error_code, address);
      return;
    }
  }
  if (unlikely(expand_stack(vma, address))) {
    bad_area(regs, error_code, address);
    return;
  }

  /*
   * Ok, we have a good vm_area for this memory access, so
   * we can handle it..
   */
  good_area:
    if (unlikely(access_error(error_code, vma))) {
      bad_area_access_error(regs, error_code, address);
      return;
    }

  /*
   * If for any reason at all we couldn't handle the fault,
   * make sure we exit gracefully rather than endlessly redo
   * the fault.  Since we never set FAULT_FLAG_RETRY_NOWAIT, if
   * we get VM_FAULT_RETRY back, the mmap_sem has been unlocked.
   */
  fault = handle_mm_fault(mm, vma, address, flags);
  major |= fault & VM_FAULT_MAJOR;

  /*
   * If we need to retry the mmap_sem has already been released,
   * and if there is a fatal signal pending there is no guarantee
   * that we made any progress. Handle this case first.
   */
  if (unlikely(fault & VM_FAULT_RETRY)) {
    /* Retry at most once */
    if (flags & FAULT_FLAG_ALLOW_RETRY) {
      flags &= ~FAULT_FLAG_ALLOW_RETRY;
      flags |= FAULT_FLAG_TRIED;
      if (!fatal_signal_pending(tsk))
        goto retry;
    }

    /* User mode? Just return to handle the fatal exception */
    if (flags & FAULT_FLAG_USER)
      return;

    /* Not returning to user mode? Handle exceptions or die: */
    no_context(regs, error_code, address, SIGBUS, BUS_ADRERR);
    return;
  }

  up_read(&mm->mmap_sem);
  if (unlikely(fault & VM_FAULT_ERROR)) {
    mm_fault_error(regs, error_code, address, fault);
    return;
  }

  /*
   * Major/minor page fault accounting. If any of the events
   * returned VM_FAULT_MAJOR, we account it as a major fault.
   */
  if (major) {
    tsk->maj_flt++;
    perf_sw_event(PERF_COUNT_SW_PAGE_FAULTS_MAJ, 1, regs, address);
  } else {
    tsk->min_flt++;
    perf_sw_event(PERF_COUNT_SW_PAGE_FAULTS_MIN, 1, regs, address);
  }

  check_v8086_mode(regs, address, tsk);
}
NOKPROBE_SYMBOL(__do_page_fault);

ifdef CONFIG_TRACING
static nokprobe_inline void
trace_page_fault_entries(unsigned long address, struct pt_regs *regs,
       unsigned long error_code)
{
  if (user_mode(regs))
    trace_page_fault_user(address, regs, error_code);
  else
    trace_page_fault_kernel(address, regs, error_code);
}

dotraplinkage void notrace
trace_do_page_fault(struct pt_regs *regs, unsigned long error_code)
{
  /*
   * The exception_enter and tracepoint processing could
   * trigger another page faults (user space callchain
   * reading) and destroy the original cr2 value, so read
   * the faulting address now.
   */
  unsigned long address = read_cr2();
  enum ctx_state prev_state;

  prev_state = exception_enter();
  trace_page_fault_entries(address, regs, error_code);
  __do_page_fault(regs, error_code, address);
  exception_exit(prev_state);
}
NOKPROBE_SYMBOL(trace_do_page_fault);
#endif /* CONFIG_TRACING */
