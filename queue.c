

#include "queue.h"
#include <stdlib.h>



void node_init(struct q_list_node *node, void *elem) {
  node->elem = elem;
  node->next = NULL;
}

void list_init(struct q_list *list) {
  list->head = NULL;
  list->tail = NULL;
}


// Enqueues a node into the queue.
void enqueue(struct q_list *list, struct q_list_node *node) {
  if (list->tail == NULL) {
    // If the queue is empty, both head and tail point to the new node.
    list->head = node;
    list->tail = node;
  } else {
    // Otherwise, add the new node to the end and update the tail.
    list->tail->next = node;
    list->tail = node;
  }
}

// Dequeues a node from the queue. Returns NULL if the queue is empty.
struct q_list_node *dequeue(struct q_list *list) {
  if (list->head == NULL) {
    return NULL; // Queue is empty.
  }

  struct q_list_node *node = list->head;
  list->head = node->next; // Move the head pointer to the next node.

  // If the queue becomes empty after dequeue, set the tail to NULL.
  if (list->head == NULL) {
    list->tail = NULL;
  }

  node->next = NULL; // Clean up the next pointer before returning.
  return node; // Return the dequeued node.
}