import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { createBrowserRouter, RouterProvider } from 'react-router-dom';
import './styles/global.css';
import App from './App.jsx';
import ServicesPage from './pages/landingPage/services/ServicesPage';
import Home from './pages/landingPage/Home';
import AboutCompany from './pages/landingPage/about/aboutCompany';
import CareerCompany from "./pages/landingPage/careers/careerCompany";
import Job1 from "./pages/landingPage/careers/job1";
import Job2 from "./pages/landingPage/careers/job2";
import AllPositions from "./pages/landingPage/careers/All-Position";
import Apply from "./pages/landingPage/careers/Apply";
import CareerContact from "./pages/landingPage/careers/CareerContact";

const router = createBrowserRouter([
  {
    path: '/',
    element: <App />,
    children: [
      {
        index: true,
        element: <Home />
      },
      {
        path: '/services', 
        element: <ServicesPage />,
      },
      {
        path: '/about',
        element: <AboutCompany />,
      },
      {
        path: '/careers',
        element: <CareerCompany />,
      },
      {
        path: '/careers/senior-fullstack-engineer',
        element: <Job1 />,
      },
      {
        path: '/careers/backend-engineer',
        element: <Job2 />,
      },
      {
        path: '/careers/all-positions',
        element: <AllPositions />,
      },  
      {
        path: '/careers/apply',
        element: <Apply />,
      },      
      {
        path: '/careers/contact',
        element: <CareerContact />,
      },          
      {
        path: '/projects',
        element: <div>Projects Page</div>,
      },
      {
        path: '/hire-me',
        element: <div>Hire Me Page</div>,
      },
      {
        path: '/learn',
        element: <div>Learn From Me Page</div>,
      },
      {
        path: '/resources',
        element: <div>Resources Page</div>,
      },
    ],
  },
]);

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <RouterProvider router={router} />
  </StrictMode>
);
