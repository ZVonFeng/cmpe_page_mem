#include <boost/interprocess/file_mapping.hpp>
#include <boost/interprocess/mapped_region.hpp>
#include <iostream>
#include <fstream>
#include <cstddef>
#include <cstdio>    //std::remove
#include <vector>

int main ()
{
   using namespace boost::interprocess;
   try{
      //Open the file mapping
      file_mapping m_file ("../server/file.bin", read_only);

      //Map the whole file in this process
      mapped_region region
         (m_file                    //What to map
         ,read_only  //Map it as read-only
         );

      //Get the address of the mapped region
      void * addr       = region.get_address();
      std::size_t size  = region.get_size();

      //Check that memory was initialized to 1
      const char *mem = static_cast<char*>(addr);
      for(std::size_t i = 0; i < size; ++i){
         if(*mem++ != 1){
            std::cout << "Error checking memory!" << std::endl;
            return 1;
         }
      }

      //Now test it reading the file
      std::filebuf fbuf;
      fbuf.open("../server/file.bin", std::ios_base::in | std::ios_base::binary); 

      //Read it to memory
      std::vector<char> vect(region.get_size(), 0);
      fbuf.sgetn(&vect[0], std::streamsize(vect.size()));

      //Check that memory was initialized to 1
      mem = static_cast<char*>(&vect[0]);
      for(std::size_t i = 0; i < size; ++i){
         if(*mem++ != 1){
            std::cout << "Error checking memory!" << std::endl;
            return 1;
         }
      }

      std::cout << "Test successful!" << std::endl;
   }
   catch(interprocess_exception &ex){
      std::remove("../server/file.bin");
      std::cout << "Unexpected exception: " << ex.what() << std::endl;
      return 1;
   }
   std::remove("../server/file.bin");
   return 0;
}
