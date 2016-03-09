#include <linux/slab.h>
#include <linux/gfp.h>
#include "stack.h"

stack_entry_t* create_stack_entry(void *data)
{
    stack_entry_t* entry = kmalloc(sizeof(struct stack_entry), GFP_KERNEL);
    if(entry) {
        entry->data = data;
    }
    return entry;
}

void delete_stack_entry(stack_entry_t *entry)
{
    kfree(entry);
}

void stack_push(struct list_head *stack, stack_entry_t *entry)
{
    list_add(&(entry->lh), stack);
}

stack_entry_t* stack_pop(struct list_head *stack)
{
    stack_entry_t* entry = list_first_entry(stack, stack_entry_t, lh);
    list_del(&entry->lh);
    return entry;
}
