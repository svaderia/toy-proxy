
#ifndef __QUEUE_H__
#define __QUEUE_H__


struct q_list_node {
  void *elem;
  struct q_list_node *next;
};

struct q_list {
  struct q_list_node *head;
  struct q_list_node *tail;
};



void node_init(struct q_list_node *node, void *elem);

void list_init(struct q_list *list);

void enqueue(struct q_list *list, struct q_list_node *node);

struct q_list_node *dequeue(struct q_list *list);

#endif /* __QUEUE_H__ */