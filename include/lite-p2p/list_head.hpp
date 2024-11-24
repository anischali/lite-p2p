#ifndef __CHAIN_LIST_H
#define __CHAIN_LIST_H

#include <stdio.h>
#include <stdlib.h>

// Inspired from list.h in linux.

/**
 * @brief a chained list structure.
 *
 */
struct list_head {
    struct list_head *next, *prev;
};



/**
 * @brief Add a new node
 *
 * @param _new  the new node to add
 * @param prev the previous node
 * @param next the next node
 */
static inline void  __list_add(struct list_head *_new, struct list_head *prev, struct list_head *next) {
    next->prev = _new;
	_new->next = next;
	_new->prev = prev;
	prev->next = _new;
}

/**
 * @brief initialize a given list head node.
 *
 */
#define INIT_HEAD_LIST(name) { &(name), &(name) }

/**
 * @brief declares and initialize a new head list node.
 *
 */
#define INIT_HEAD(name) \
    struct list_head name = INIT_HEAD_LIST(name)


/**
 * @brief Initialize a node from its pointer.
 *
 * @param list the node to initialize.
 */
static inline void INIT_LIST_HEAD(struct list_head *list)
{
        list->next = list;
        list->prev = list;
}


/**
 * @brief check if a list is empty.
 *
 * @param head a list head.
 * @return int 1 if a list head is empty, 0 otherwise.
 */
static inline int list_empty(struct list_head *head) {
    return head->next == head;
};

/**
 * @brief add a new node to the list tail.
 *
 * @param value the new node to add to list head.
 * @param head the list on which we add a new node.
 */
static inline void  list_add_tail(struct list_head *value, struct list_head *head) {
    __list_add(value, head->prev, head);
}


/**
 * @brief gives the offset of given member of a structure.
 *
 */
#undef offsetof
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)

/**
 * @brief gets the root address of given structure member.
 *
 */
#define container_of(ptr, type, member) ({                      \
	const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
	(type *)( (char *)__mptr - offsetof(type,member) );})


/**
 * @brief gets the list entry or root address of a list node.
 *
 */
#define list_entry(ptr, type, member) \
	container_of(ptr, type, member)

/**
 * @brief gets the list last entry
 *
 */
#define list_last_entry(ptr, type, member) \
	list_entry((ptr)->prev, type, member)

/**
 * @brief gets the first element of a list
 * 
 */
#define list_first_entry(ptr, type, member) \
	list_entry((ptr)->next, type, member)

/**
 * @brief a loop foreach element of list head.
 *
 */
#define list_for_each_entry(instance, array, member)				\
	for (instance = list_entry((array)->next, typeof(*instance), member);	\
	     &instance->member != (array); 	\
	     instance = list_entry(instance->member.next, typeof(*instance), member))

/**
 * @brief a safe loop foreach element of list head.
 *          the safe because we a saved the current
 *          node at each looped element, you can use
 *          it when you need to remove an element.
 *
 */
#define list_for_each_entry_safe(instance, save, array, member)			\
	for (instance = list_entry((array)->next, typeof(*instance), member),	\
		save = list_entry(instance->member.next, typeof(*instance), member);	\
	     &(instance)->member != (array);					\
	     instance = save, save = list_entry(save->member.next, typeof(*save), member))

/**
 * @brief a loop foreach element of list head in the reverse order.
 *
 */
#define list_for_each_entry_reverse(instance, array, member)                        \
        for (instance = list_last_entry(array, __typeof__(*instance), member); &instance->member != (array); \
            instance = list_entry(instance->member.prev, __typeof__(*instance), member))


/**
 * @brief removes a given element from a list.
 *
 * @param prev the previous element
 * @param next the next element
 */
static inline void __list_del(struct list_head *prev, struct list_head *next)
{
	next->prev = prev;
	prev->next = next;
}

#define LIST_POISON1  ((void *) 0x00100100)
#define LIST_POISON2  ((void *) 0x00200200)
/**
 * @brief  list_del - deletes entry from list.
 *
 * @param entry: the element to delete from the list.
 * Note: list_empty() on entry does not return true after this, the entry is
 * in an undefined state.
 */
static inline void list_del(struct list_head *entry)
{
	__list_del(entry->prev, entry->next);
	entry->next = (struct list_head*)LIST_POISON1;
	entry->prev = (struct list_head*)LIST_POISON2;
}

#endif