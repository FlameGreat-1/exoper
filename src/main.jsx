import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { createBrowserRouter, RouterProvider } from 'react-router-dom';
import './styles/global.css';
import App from './App.jsx';
import ServicesPage from './pages/landingPage/services/ServicesPage';
import PricingPage from "./pages/landingPage/pricing/pricingPage";
import Home from './pages/landingPage/Home';
import AboutCompany from './pages/landingPage/about/aboutCompany';
import CareerCompany from "./pages/landingPage/careers/careerCompany";
import Job1 from "./pages/landingPage/careers/job1";
import Job2 from "./pages/landingPage/careers/job2";
import Job3 from "./pages/landingPage/careers/job3";
import Job4 from "./pages/landingPage/careers/job4";
import Job5 from "./pages/landingPage/careers/job5";
import Job6 from "./pages/landingPage/careers/job6";
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
        path: '/careers/senior-product-marketer',
        element: <Job3 />,
      },
      {
        path: '/careers/devops-engineer',
        element: <Job4 />,
      },
      {
        path: '/careers/senior-ml-engineer',
        element: <Job5 />,
      },
      {
        path: '/careers/frontend-engineer',
        element: <Job6 />,
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
        path: '/pricing',
        element: <PricingPage />,
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
