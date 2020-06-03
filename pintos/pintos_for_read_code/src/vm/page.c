#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include <threads/malloc.h>
#include <threads/palloc.h>
#include "filesys/file.h"
#include "vm/page.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "userprog/syscall.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "lib/kernel/list.h"

/* 해시 테이블 초기화 */
void vm_init(struct hash *vm)
{
    /* hash_init()으로 해시테이블 초기화 */
	hash_init(vm, vm_hash_func, vm_less_func, NULL);
}

/*vm_entry의 vaddr을 인자값으로 hash_int() 함수를 사용하여 해시 값 반환*/
static unsigned vm_hash_func (const struct hash_elem *e,void *aux)
{
    /* hash_entry()로 element에 대한 vm_entry 구조체 검색 */
    struct vm_entry *entry = hash_entry(e, struct vm_entry, elem);
    /* hash_int()를 이용해서 vm_entry의 멤버 vaddr에 대한 해시값을
        구하고 반환 */
    return hash_int((int)entry->vaddr);
}

/*입력된 두 hash_elem의 vaddr 비교, a가 작을 시 true*/
static bool vm_less_func (const struct hash_elem *a, const struct hash_elem *b,
                            void *aux)
{
    /* hash_entry()로 각각의 element에 대한 vm_entry 구조체를 얻은
      후 vaddr 비교 (b가 크다면 true, a가 크다면 false) */
    struct vm_entry *entryA = hash_entry(a, struct vm_entry, elem);
    struct vm_entry *entryB = hash_entry(b, struct vm_entry, elem);

    // hash_int((int)entryA->vaddr) > hash_int((int)entryB->vaddr)
    if(entryA->vaddr > entryB->vaddr)
        return false;
    else if (entryA->vaddr < entryB->vaddr)
        return true;
    else
        return false;   // the function is asking 'less than'
}

/*vm_entry를 해시 테이블에 삽입, 성공 시 true*/
bool insert_vme (struct hash *vm, struct vm_entry *vme)
{
    /* hash_insert()함수 사용 */
    if(hash_insert(vm, &vme->elem) == NULL)
        return true;
    else
        return false;
}

/*vm_entry를 해시 테이블에서 제거*/
bool delete_vme (struct hash *vm, struct vm_entry *vme)
{
    /* hash_delete()함수 사용 */
    if(hash_delete(vm, &vme->elem) != NULL){
        free(vme);
        return true;
    }
    else{
        free(vme);
        return false;
    }
}

/*인자로 받은 vaddr에 해당하는 vm_entry를 검색 후 반환*/
struct vm_entry *find_vme (void *vaddr)
{
    /* pg_round_down()으로 vaddr의 페이지 번호를 얻음 */
    void * vaddr_get = pg_round_down(vaddr);
    struct vm_entry entry;
    entry.vaddr = vaddr_get;

    struct hash_elem *element;
    /* hash_find() 함수를 사용해서 hash_elem 구조체 얻음 */
    element = hash_find(&thread_current()->vm, &vme.elem);
    /* 만약 존재하지 않는다면 NULL 리턴 */
    if(element == NULL)
        return NULL;
    /* hash_entry()로 해당 hash_elem의 vm_entry 구조체 리턴 */
    return hash_entry(element, struct vm_entry, elem);
}

static void vm_destroy_func(struct hash_elem *e, void *aux UNUSED)
{
	struct vm_entry *vme = hash_entry(e, struct vm_entry, elem);
	void *physical_address;
	/* if virtual address is loaded on physical memory */
	if(vme->is_loaded == true)
	{
		/*get physical_address and free page */
		physical_address = pagedir_get_page(thread_current()->pagedir, vme->vaddr);
		palloc_free_page(physical_address);
		/* clear page table */
		pagedir_clear_page(thread_current()->pagedir, vme->vaddr);
	}
	/* free vm_entry */
	free(vme);
}

/*해시 테이블의 버킷리스트와 vm_entry들을 제거*/
vm_destroy (struct hash *vm)
{
{
    /* hash_destroy()으로 해시테이블의 버킷리스트와 vm_entry들을 제거 */
    hash_destroy(vm, vm_destroy_func);  //**********************************
}

bool load_file(void *kaddr, struct vm_entry *vme)
{
	bool result = false;   
	/* file read and if success, return true */
	/* read vm_entry's file to physical memory.*/
	if((int)vme->read_bytes == file_read_at(vme->file, kaddr, vme->read_bytes, vme->offset))
	{
		result = true;
		memset(kaddr + vme->read_bytes, 0, vme->zero_bytes);
	} 
	return result;
}