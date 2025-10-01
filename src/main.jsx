import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { createBrowserRouter, RouterProvider } from 'react-router-dom';
import './styles/global.css'; // Updated CSS import path
import App from './App.jsx';
import ServicesPage from './pages/landingPage/services/ServicesPage'; // Import the combined Services component
import Home from './pages/landingPage/Home'; // Import the new Home component

// Create router with routes
const router = createBrowserRouter([
  {
    path: '/',
    element: <App />,
    children: [
      {
        index: true,
        element: <Home /> // Home component that includes Hero, Services1, and Services2
      },
      {
        path: '/services', 
        element: <ServicesPage />, // Use the combined ServicesPage component
      },
      {
        path: '/about',
        element: <div>About Page</div>, // Placeholder for About page
      },
      {
        path: '/projects',
        element: <div>Projects Page</div>, // Placeholder for Projects page
      },
      {
        path: '/hire-me',
        element: <div>Hire Me Page</div>, // Placeholder for Hire Me page
      },
      {
        path: '/learn',
        element: <div>Learn From Me Page</div>, // Placeholder for Learn page
      },
      {
        path: '/resources',
        element: <div>Resources Page</div>, // Placeholder for Resources page
      },
    ],
  },
]);

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <RouterProvider router={router} />
  </StrictMode>
);
