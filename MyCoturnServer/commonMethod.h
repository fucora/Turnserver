#pragma once
#ifndef COMMONMETHOD_H
#define COMMONMETHOD_H

#include "commonTypes.h"

class commonMethod
{
public:
	commonMethod();
	~commonMethod();

	size_t ioa_network_buffer_get_size(ioa_network_buffer_handle nbh);

	u08bits * ioa_network_buffer_data(ioa_network_buffer_handle nbh);

	void ioa_network_buffer_set_size(ioa_network_buffer_handle nbh, size_t len);


};

#endif

 
