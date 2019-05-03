#include "commonMethod.h"


typedef struct _stun_buffer_list_elem {
	struct _stun_buffer_list_elem *next;
	stun_buffer buf;
} stun_buffer_list_elem;


commonMethod::commonMethod()
{
}


commonMethod::~commonMethod()
{
}

size_t commonMethod::ioa_network_buffer_get_size(ioa_network_buffer_handle nbh)
{
	if (!nbh)
		return 0;
	else {
		stun_buffer_list_elem *buf_elem = (stun_buffer_list_elem *)nbh;
		return (size_t)(buf_elem->buf.len);
	}
}

u08bits* commonMethod::ioa_network_buffer_data(ioa_network_buffer_handle nbh)
{
	stun_buffer_list_elem *buf_elem = (stun_buffer_list_elem *)nbh;
	return buf_elem->buf.buf + buf_elem->buf.offset - buf_elem->buf.coffset;
}

void commonMethod::ioa_network_buffer_set_size(ioa_network_buffer_handle nbh, size_t len)
{
	stun_buffer_list_elem *buf_elem = (stun_buffer_list_elem *)nbh;
	buf_elem->buf.len = (size_t)len;
}

 