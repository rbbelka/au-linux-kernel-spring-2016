#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/slab.h>

#include "stack.h"
#include "assert.h"

static void __init test_stack(void)
{
    LIST_HEAD(data_stack);
    stack_entry_t *tos = NULL;
    const char *tos_data = NULL;
    const char* test_data[] = { "1", "2", "3", "4" };
    long i = 0;

    pr_alert("Testing basic stack");

    for (i = 0; i != ARRAY_SIZE(test_data); ++i) {
        stack_push(&data_stack,
            create_stack_entry((void*)test_data[i])
        );
    }

    for (i = ARRAY_SIZE(test_data) - 1; i >= 0; --i) {
        tos = stack_pop(&data_stack);
        tos_data = STACK_ENTRY_DATA(tos, const char*);
        delete_stack_entry(tos);
        printk(KERN_ALERT "%s == %s\n", tos_data, test_data[i]);
        assert(!strcmp(tos_data, test_data[i]));
    }

    assert(stack_empty(&data_stack));
}

static int __init print_processes_backwards(void)
{
    int ret = 0;
    stack_entry_t *tos = NULL;
    char *buffer = NULL;
    struct task_struct *task;
    LIST_HEAD(processes);
 
    for_each_process(task) {
        char* buffer = (char *)kmalloc(sizeof(task->comm), GFP_KERNEL);
	if(!buffer)
	{
	    ret = -ENOMEM;
	    break;
	}
	
	get_task_comm(buffer, task);	

	tos = create_stack_entry((void*)buffer);
 	if(!tos)
	{
	    kfree(tos);
	    ret = -ENOMEM;
	    break;
	}
	
        stack_push(&processes, tos);
    }
 
    while (!stack_empty(&processes)) {
        tos = stack_pop(&processes);
        buffer = STACK_ENTRY_DATA(tos, char*);
        printk(KERN_ALERT "%s\n", buffer);
	delete_stack_entry(tos); 
 	kfree(buffer);
    }
    return ret;
}

static int __init ll_init(void)
{
    printk(KERN_ALERT "Hello, linked_lists\n");
    test_stack();
    print_processes_backwards();
    return 0;
}

static void __exit ll_exit(void)
{
    printk(KERN_ALERT "Goodbye, linked_lists!\n");
}

module_init(ll_init);
module_exit(ll_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Linked list exercise module");
MODULE_AUTHOR("Kernel hacker!");
