import React from 'react'
 import { IoSearch } from "react-icons/io5";
 
 const Search = () => {
   return (
     <div className='w-full min-w-[300px] lg:min-w-[420px] h-12 rounded-lg border p-1 overflow-hidden flex items-center text-neutral-500'>
         <button className='flex justify-center items-center h-full p-3 '>
         <IoSearch size={22}/>
         </button>
         <div>
             Search "Milk"
         </div>
         </div>
   )
 }
 
 export default Search
