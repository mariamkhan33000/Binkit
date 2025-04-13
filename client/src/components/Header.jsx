import React from 'react'
import logo from '../assets/logo.png'
import Search from './Search'
import { Link } from 'react-router-dom'
import { FaRegCircleUser } from "react-icons/fa6";


const Header = () => {
  return (
    <header className='h-20 shadow-md sticky top-0 bg-red-400 flex flex-col justify-center gap-1'>
      <div className='container mx-auto h-full flex items-center justify-between'>
        {/* Logo */}

        <div className='h-full'>
            <Link to={'/'} className='h-full flex justify-center items-center'>
                <img src={logo} width={170} height={60} alt="Logo" className='hidden lg:block' />
                <img src={logo} width={120} height={60} alt="Logo" className='lg:hidden' />
            </Link>
        </div>
        {/* Search Bar */}
        <div className='hidden lg:block'>
            <Search/>
        </div>
        {/* login my cart */}
        <div>
            <button className='text-neutral-500 lg:hidden'>
              <FaRegCircleUser size={26} />
            </button>
            <div className='hidden  lg:block'>
              login my cart
            </div>
        </div>
      </div>
      <div className='container mx-auto px-2 lg:hidden'>
        <Search/>
      </div>
    </header>
  )
}

export default Header
