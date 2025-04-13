import React from 'react'
import Header from './components/Header'
import Footer from './components/Footer'
import { Outlet } from 'react-router-dom'

const App = () => {
  return (
    <>
      <Header/>
      <main className='min-h-[78vh]'>
        <Outlet/>
      </main>
      <Footer/>
    </>
  )
}

export default App
